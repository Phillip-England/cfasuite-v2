package apiapp

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"image/color"
	stddraw "image/draw"
	"image/png"
	"io"
	"log"
	"math"
	"mime/multipart"
	"net"
	"net/http"
	"net/mail"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/extrame/xls"
	"github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/types"
	"github.com/phillip-england/cfasuite/internal/middleware"
	"github.com/phillip-england/cfasuite/internal/security"
	"github.com/ulikunitz/xz"
	"github.com/xuri/excelize/v2"
	xdraw "golang.org/x/image/draw"
	"golang.org/x/image/webp"
	_ "image/jpeg"
)

const (
	sessionCookieName                = "cfasuite_session"
	csrfHeaderName                   = "X-CSRF-Token"
	defaultPerPage                   = 25
	maxPerPage                       = 25
	deleteLocationConfirmationPhrase = "I CHOOSE TO DELETE THIS LOCATION AND ALL OF ITS DATA"
	userRoleAdmin                    = "admin"
	userRoleRestaurant               = "restaurant"
	userRoleTeam                     = "team"
	teamAccessLevelNoAccess          = "no_access"
	questionResponseTypeText         = "text"
	questionResponseTypeMultiple     = "multiple_choice"
	questionResponseTypeNumber       = "number"
	uniformSystemKeyShoes            = "shoes"
	shoeShippingCentsPerItem         = int64(1000)
	shoeTaxPercent                   = int64(10)
	pdfcpuVersion                    = "v0.11.1"
)

var (
	errNotFound                   = errors.New("not found")
	errPINInUse                   = errors.New("pin in use")
	shoeStylePattern              = regexp.MustCompile(`^\d{5}$`)
	zipCodePattern                = regexp.MustCompile(`^\d{5}(-\d{4})?$`)
	cityPattern                   = regexp.MustCompile(`^[A-Z][A-Z .'-]{0,99}$`)
	w4CurrencyAmountPattern       = regexp.MustCompile(`^\d+(?:\.\d{1,2})?$`)
	defaultLocationDepartments = []string{"BOH", "FOH", "RLT", "CST", "EXECUTIVE", "PARTNER"}
	defaultLocationPayBands    = []struct {
		Name           string
		PayType        string
		PayAmountCents int64
	}{
		{Name: "Team Member I", PayType: "hourly", PayAmountCents: 1200},
		{Name: "Team Member II", PayType: "hourly", PayAmountCents: 1350},
		{Name: "Team Leader", PayType: "hourly", PayAmountCents: 1600},
		{Name: "Manager", PayType: "salary", PayAmountCents: 5200000},
	}
	defaultLocationInterviewTypes = []string{
		"Phone Interview",
		"Face to Face Interview",
		"Final Interview",
	}
	ensurePdfcpuOnce sync.Once
	ensurePdfcpuErr  error
)

type contextKey string

const (
	userContextKey    contextKey = "user"
	sessionContextKey contextKey = "session"
)

type Config struct {
	Addr          string
	DBPath        string
	AdminUsername string
	AdminPassword string
	SessionTTL    time.Duration
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type teamLoginRequest struct {
	Token          string `json:"token"`
	LocationNumber string `json:"locationNumber"`
	TimePunchName  string `json:"timePunchName"`
	Pin            string `json:"pin"`
}

type teamImpersonateRequest struct {
	LocationNumber string `json:"locationNumber"`
	TimePunchName  string `json:"timePunchName"`
}

type restaurantImpersonateRequest struct {
	LocationNumber string `json:"locationNumber"`
}

type createLocationRequest struct {
	Name                 string `json:"name"`
	Number               string `json:"number"`
	Email                string `json:"email"`
	Phone                string `json:"phone"`
	EmployerRepSignature string `json:"employerRepSignature"`
	BusinessName         string `json:"businessName"`
	BusinessStreet       string `json:"businessStreet"`
	BusinessCity         string `json:"businessCity"`
	BusinessState        string `json:"businessState"`
	BusinessEIN          string `json:"businessEin"`
	BusinessAddress      string `json:"businessAddress"`
}

type updateLocationRequest struct {
	Name string `json:"name"`
}

type deleteLocationRequest struct {
	ConfirmationText string `json:"confirmationText"`
}

type updateEmployeeDepartmentRequest struct {
	Department string `json:"department"`
}

type updateEmployeeJobRequest struct {
	JobID int64 `json:"jobId"`
}

type updateEmployeePayBandRequest struct {
	PayBandID int64 `json:"payBandId"`
}

type updateEmployeeClockInPINRequest struct {
	PIN string `json:"pin"`
}

type updateEmployeeDetailsRequest struct {
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
	Birthday  string `json:"birthday"`
	Email     string `json:"email"`
	Phone     string `json:"phone"`
	Address   string `json:"address"`
	AptNumber string `json:"aptNumber"`
	City      string `json:"city"`
	State     string `json:"state"`
	ZipCode   string `json:"zipCode"`
	PayType   string `json:"payType"`
	PayAmount string `json:"payAmount"`
}

type createTimePunchEntryRequest struct {
	TimePunchName            string `json:"timePunchName"`
	PunchDate                string `json:"punchDate"`
	TimeIn                   string `json:"timeIn"`
	TimeOut                  string `json:"timeOut"`
	Note                     string `json:"note"`
	ForgotBreakClockInReturn bool   `json:"forgotBreakClockInReturn"`
}

type createTimeOffRequestRequest struct {
	TimePunchName string `json:"timePunchName"`
	StartDate     string `json:"startDate"`
	EndDate       string `json:"endDate"`
}

type createBusinessDayRequest struct {
	BusinessDate string `json:"businessDate"`
	StartDate    string `json:"startDate"`
	EndDate      string `json:"endDate"`
}

type updateBusinessDayRequest struct {
	TotalSales string `json:"totalSales"`
	LaborHours string `json:"laborHours"`
}

type createUniformItemRequest struct {
	Name       string `json:"name"`
	Price      string `json:"price"`
	Sizes      string `json:"sizes"`
	SizeFields string `json:"sizeFields"`
}

type updateUniformItemRequest struct {
	Name       string `json:"name"`
	Price      string `json:"price"`
	Sizes      string `json:"sizes"`
	SizeFields string `json:"sizeFields"`
}

type createCandidateRequest struct {
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
	Phone     string `json:"phone"`
}

type createCandidateValueRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type updateCandidateValueRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type createCandidateInterviewNameRequest struct {
	Name     string `json:"name"`
	Priority *int64 `json:"priority,omitempty"`
}

type updateCandidateInterviewNameRequest struct {
	Priority *int64 `json:"priority,omitempty"`
}

type createCandidateInterviewRequest struct {
	InterviewerTimePunchName string            `json:"interviewerTimePunchName"`
	InterviewType            string            `json:"interviewType"`
	Grades                   map[string]string `json:"grades"`
	GradeComments            map[string]string `json:"gradeComments"`
	QuestionAnswers          map[string]string `json:"questionAnswers"`
	Notes                    string            `json:"notes"`
}

type updateCandidateDecisionRequest struct {
	Decision     string `json:"decision"`
	DepartmentID int64  `json:"departmentId"`
	JobID        int64  `json:"jobId"`
	PayBandID    int64  `json:"payBandId"`
	PayType      string `json:"payType"`
	PayAmount    string `json:"payAmount"`
	FirstName    string `json:"firstName"`
	LastName     string `json:"lastName"`
	Birthday     string `json:"birthday"`
	Email        string `json:"email"`
	Phone        string `json:"phone"`
	Address      string `json:"address"`
	AptNumber    string `json:"aptNumber"`
	City         string `json:"city"`
	State        string `json:"state"`
	ZipCode      string `json:"zipCode"`
}

type createDepartmentRequest struct {
	Name string `json:"name"`
}

type createJobRequest struct {
	Name      string `json:"name"`
	PayType   string `json:"payType"`
	PayAmount string `json:"payAmount"`
}

type assignJobDepartmentsRequest struct {
	DepartmentIDs []int64 `json:"departmentIds"`
	DepartmentID  int64   `json:"departmentId"`
}

type createEmployeeAdditionalCompensationRequest struct {
	Label  string `json:"label"`
	Amount string `json:"amount"`
}

type createCandidateInterviewLinkRequest struct {
	InterviewerTimePunchName string `json:"interviewerTimePunchName"`
	InterviewType            string `json:"interviewType"`
	ScheduledAt              string `json:"scheduledAt"`
}

type createCandidateInterviewQuestionRequest struct {
	InterviewNameID  int64    `json:"interviewNameId"`
	InterviewNameIDs []int64  `json:"interviewNameIds"`
	Question         string   `json:"question"`
	ResponseType     string   `json:"responseType"`
	ResponseOptions  []string `json:"responseOptions"`
}

type updateCandidateInterviewQuestionRequest struct {
	InterviewNameID  int64    `json:"interviewNameId"`
	InterviewNameIDs []int64  `json:"interviewNameIds"`
	Question         *string  `json:"question,omitempty"`
	ResponseType     *string  `json:"responseType,omitempty"`
	ResponseOptions  []string `json:"responseOptions,omitempty"`
}

type createUniformOrderRequest struct {
	TimePunchName string                          `json:"timePunchName"`
	Items         []createUniformOrderLineRequest `json:"items"`
}

type createUniformOrderLineRequest struct {
	ItemID         int64             `json:"itemId"`
	Size           string            `json:"size,omitempty"`
	SizeSelections map[string]string `json:"sizeSelections,omitempty"`
	SizeValues     []string          `json:"sizeValues,omitempty"`
	OrderType      string            `json:"orderType,omitempty"`
	ShoeItemNumber string            `json:"shoeItemNumber,omitempty"`
	ShoePrice      string            `json:"shoePrice,omitempty"`
	ShoeURL        string            `json:"shoeUrl,omitempty"`
	Note           string            `json:"note,omitempty"`
	Quantity       int64             `json:"quantity"`
}

type packetSignatureRequest struct {
	DocumentType      string `json:"documentType"`
	SignatureDataURL  string `json:"signatureDataUrl"`
	SignerDisplayName string `json:"signerDisplayName"`
}

type moveUniformImageRequest struct {
	Direction string `json:"direction"`
}

type updateUniformOrderLineSettlementRequest struct {
	Purchased   bool   `json:"purchased"`
	ChargedBack string `json:"chargedBack"`
}

type userRecord struct {
	ID             int64
	Username       string
	IsAdmin        bool
	Role           string
	AccessLevel    string
	LocationNumber string
	TimePunchName  string
}

type sessionRecord struct {
	ID        string
	UserID    int64
	CSRFToken string
	ExpiresAt time.Time
}

type location struct {
	Name      string    `json:"name"`
	Number    string    `json:"number"`
	Email     string    `json:"email"`
	Phone     string    `json:"phone"`
	CreatedAt time.Time `json:"createdAt"`
}

type employee struct {
	FirstName             string `json:"firstName"`
	LastName              string `json:"lastName"`
	TimePunchName         string `json:"timePunchName"`
	EmployeeNumber        string `json:"employeeNumber,omitempty"`
	Department            string `json:"department"`
	DepartmentID          int64  `json:"departmentId"`
	JobID                 int64  `json:"jobId"`
	JobName               string `json:"jobName"`
	PayBandID             int64  `json:"payBandId"`
	PayBandName           string `json:"payBandName"`
	PayType               string `json:"payType,omitempty"`
	PayAmountCents        int64  `json:"payAmountCents,omitempty"`
	AdditionalCompCents   int64  `json:"additionalCompCents,omitempty"`
	EffectivePayCents     int64  `json:"effectivePayCents,omitempty"`
	Birthday              string `json:"birthday,omitempty"`
	Email                 string `json:"email,omitempty"`
	Phone                 string `json:"phone,omitempty"`
	Address               string `json:"address,omitempty"`
	AptNumber             string `json:"aptNumber,omitempty"`
	City                  string `json:"city,omitempty"`
	State                 string `json:"state,omitempty"`
	ZipCode               string `json:"zipCode,omitempty"`
	HasPhoto              bool   `json:"hasPhoto"`
	HasClockInPIN         bool   `json:"hasClockInPin"`
	HasCompletedPaperwork bool   `json:"hasCompletedPaperwork"`
	ArchivedAt            string `json:"archivedAt,omitempty"`
}

type locationDepartment struct {
	ID             int64     `json:"id"`
	LocationNumber string    `json:"locationNumber"`
	Name           string    `json:"name"`
	CreatedAt      time.Time `json:"createdAt"`
}

type locationJob struct {
	ID              int64     `json:"id"`
	LocationNumber  string    `json:"locationNumber"`
	DepartmentID    int64     `json:"departmentId"`
	DepartmentName  string    `json:"departmentName"`
	DepartmentIDs   []int64   `json:"departmentIds"`
	DepartmentNames []string  `json:"departmentNames"`
	Name            string    `json:"name"`
	PayType         string    `json:"payType"`
	PayAmountCents  int64     `json:"payAmountCents"`
	CreatedAt       time.Time `json:"createdAt"`
}

type employeeAdditionalCompensation struct {
	ID             int64     `json:"id"`
	LocationNumber string    `json:"locationNumber"`
	TimePunchName  string    `json:"timePunchName"`
	Label          string    `json:"label"`
	AmountCents    int64     `json:"amountCents"`
	CreatedAt      time.Time `json:"createdAt"`
}

type employeeI9Form struct {
	LocationNumber string    `json:"locationNumber"`
	TimePunchName  string    `json:"timePunchName"`
	FileName       string    `json:"fileName"`
	FileMime       string    `json:"fileMime"`
	UpdatedAt      time.Time `json:"updatedAt"`
	CreatedAt      time.Time `json:"createdAt"`
	HasFile        bool      `json:"hasFile"`
}

type employeeI9Document struct {
	ID             int64     `json:"id"`
	LocationNumber string    `json:"locationNumber"`
	TimePunchName  string    `json:"timePunchName"`
	ListType       string    `json:"listType,omitempty"`
	DocumentTitle  string    `json:"documentTitle,omitempty"`
	IssuingAuth    string    `json:"issuingAuthority,omitempty"`
	DocumentNumber string    `json:"documentNumber,omitempty"`
	ExpirationDate string    `json:"expirationDate,omitempty"`
	FileName       string    `json:"fileName"`
	FileMime       string    `json:"fileMime"`
	CreatedAt      time.Time `json:"createdAt"`
}

type paperworkHistoryEntry struct {
	ID        int64     `json:"id"`
	FileName  string    `json:"fileName"`
	FileMime  string    `json:"fileMime"`
	CreatedAt time.Time `json:"createdAt"`
}

type documentTemplate struct {
	ID                int64
	DocumentType      string
	TemplatePath      string
	SignaturePage     int
	SignatureTopLeftX float64
	SignatureTopLeftY float64
	SignatureWidth    float64
	SignatureHeight   float64
	SignatureZoom     int
	FormFieldName     string
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

type employeeDocumentPacket struct {
	ID             int64
	LocationNumber string
	TimePunchName  string
	Status         string
	CreatedAt      time.Time
	UpdatedAt      time.Time
	FinalizedAt    time.Time
}

type packetDocument struct {
	ID                 int64
	PacketID           int64
	DocumentType       string
	Status             string
	FileData           []byte
	FileMime           string
	FileName           string
	SignedFileData     []byte
	SignedFileMime     string
	SignedFileName     string
	SignaturePage      int
	SignatureTopLeftX  float64
	SignatureTopLeftY  float64
	SignatureWidth     float64
	SignatureHeight    float64
	SignatureZoom      int
	FormFieldName      string
	RequiredSignatures int64
	SignedCount        int64
	SignedAt           time.Time
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

type archivedEmployeeRecord struct {
	ID             int64
	LocationNumber string
	TimePunchName  string
	EmployeeNumber string
	FirstName      string
	LastName       string
	Department     string
	JobID          int64
	Birthday       string
	Email          string
	Phone          string
	Address        string
	AptNumber      string
	City           string
	State          string
	ZipCode        string
	ProfileImage   string
	ProfileMime    string
	ArchivedAt     time.Time
}

type bioEmployeeRow struct {
	EmployeeNumber string
	FirstName      string
	LastName       string
	TimePunchName  string
	Terminated     bool
}

type birthdateRow struct {
	TimePunchName string
	Birthday      string
}

type sqliteStore struct {
	dbPath string
}

type employeePhotoToken struct {
	Token         string
	LocationNum   string
	TimePunchName string
	ExpiresAt     time.Time
	UsedAt        *time.Time
}

type employeePaperworkToken struct {
	Token         string
	LocationNum   string
	TimePunchName string
	ExpiresAt     time.Time
}

type candidateInterviewToken struct {
	Token                    string
	LocationNumber           string
	CandidateID              int64
	InterviewerTimePunchName string
	InterviewType            string
	ScheduledAt              time.Time
	ExpiresAt                time.Time
	UsedAt                   *time.Time
}

type locationTimePunchToken struct {
	Token          string
	LocationNumber string
}

type locationTimeOffToken struct {
	Token          string
	LocationNumber string
}

type timePunchEntry struct {
	ID                       int64     `json:"id"`
	LocationNum              string    `json:"locationNumber"`
	TimePunchName            string    `json:"timePunchName"`
	PunchDate                string    `json:"punchDate"`
	TimeIn                   string    `json:"timeIn"`
	TimeOut                  string    `json:"timeOut"`
	Note                     string    `json:"note"`
	ForgotBreakClockInReturn bool      `json:"forgotBreakClockInReturn"`
	ArchivedAt               time.Time `json:"archivedAt,omitempty"`
	CreatedAt                time.Time `json:"createdAt"`
}

type timeOffRequest struct {
	ID            int64     `json:"id"`
	LocationNum   string    `json:"locationNumber"`
	TimePunchName string    `json:"timePunchName"`
	StartDate     string    `json:"startDate"`
	EndDate       string    `json:"endDate"`
	CreatedAt     time.Time `json:"createdAt"`
	ArchivedAt    time.Time `json:"archivedAt,omitempty"`
}

type businessDay struct {
	ID           int64     `json:"id"`
	LocationNum  string    `json:"locationNumber"`
	BusinessDate string    `json:"businessDate"`
	TotalSales   float64   `json:"totalSales"`
	LaborHours   float64   `json:"laborHours"`
	CreatedAt    time.Time `json:"createdAt"`
	UpdatedAt    time.Time `json:"updatedAt"`
}

type locationUniformToken struct {
	Token          string
	LocationNumber string
}

type locationSettings struct {
	LocationNumber       string   `json:"locationNumber"`
	EmployerRepSignature string   `json:"employerRepSignature"`
	BusinessName         string   `json:"businessName"`
	BusinessStreet       string   `json:"businessStreet"`
	BusinessCity         string   `json:"businessCity"`
	BusinessState        string   `json:"businessState"`
	BusinessEIN          string   `json:"businessEin"`
	BusinessAddress      string   `json:"businessAddress"`
	W4EmployerName       string   `json:"w4EmployerName"`
	W4EmployerStreet     string   `json:"w4EmployerStreet"`
	W4EmployerCity       string   `json:"w4EmployerCity"`
	W4EmployerState      string   `json:"w4EmployerState"`
	W4EmployerEIN        string   `json:"w4EmployerEin"`
	W4EmployerAddress    string   `json:"w4EmployerAddress"`
	Departments          []string `json:"departments"`
	RestaurantUsername   string   `json:"restaurantUsername"`
}

type uniformItem struct {
	ID          int64              `json:"id"`
	LocationNum string             `json:"locationNumber"`
	Name        string             `json:"name"`
	Price       float64            `json:"price"`
	Enabled     bool               `json:"enabled"`
	ImageData   string             `json:"imageData"`
	ImageMime   string             `json:"imageMime"`
	Images      []uniformItemImage `json:"images"`
	Sizes       []string           `json:"sizes"`
	SizeFields  []uniformSizeField `json:"sizeFields"`
	SystemKey   string             `json:"systemKey"`
	CreatedAt   time.Time          `json:"createdAt"`
	UpdatedAt   time.Time          `json:"updatedAt"`
}

type uniformSizeField struct {
	Label   string   `json:"label"`
	Options []string `json:"options"`
}

type uniformItemImage struct {
	ID        int64  `json:"id"`
	ItemID    int64  `json:"itemId"`
	ImageData string `json:"imageData"`
	ImageMime string `json:"imageMime"`
	SortOrder int64  `json:"sortOrder"`
}

type uniformOrder struct {
	ID            int64              `json:"id"`
	LocationNum   string             `json:"locationNumber"`
	TimePunchName string             `json:"timePunchName"`
	ItemsSummary  string             `json:"itemsSummary"`
	Lines         []uniformOrderLine `json:"lines"`
	Total         float64            `json:"total"`
	CreatedAt     time.Time          `json:"createdAt"`
	ArchivedAt    time.Time          `json:"archivedAt,omitempty"`
}

type uniformOrderLine struct {
	ID          int64     `json:"id"`
	OrderID     int64     `json:"orderId"`
	ItemID      int64     `json:"itemId"`
	ItemName    string    `json:"itemName"`
	ItemNumber  string    `json:"itemNumber"`
	SizeOption  string    `json:"sizeOption"`
	ExternalURL string    `json:"externalUrl"`
	Note        string    `json:"note"`
	Quantity    int64     `json:"quantity"`
	UnitPrice   float64   `json:"unitPrice"`
	LineTotal   float64   `json:"lineTotal"`
	Purchased   bool      `json:"purchased"`
	PurchasedAt time.Time `json:"purchasedAt,omitempty"`
	ChargedBack float64   `json:"chargedBack"`
	Remaining   float64   `json:"remaining"`
}

type uniformOrderLineInput struct {
	ItemID         int64
	ItemName       string
	ItemNumber     string
	Size           string
	ExternalURL    string
	Note           string
	Quantity       int64
	UnitPriceCents int64
}

type candidate struct {
	ID                  int64                `json:"id"`
	LocationNumber      string               `json:"locationNumber"`
	FirstName           string               `json:"firstName"`
	LastName            string               `json:"lastName"`
	Phone               string               `json:"phone"`
	Status              string               `json:"status"`
	HiredTimePunchName  string               `json:"hiredTimePunchName"`
	CreatedAt           time.Time            `json:"createdAt"`
	UpdatedAt           time.Time            `json:"updatedAt"`
	ArchivedAt          time.Time            `json:"archivedAt,omitempty"`
	Interviews          []candidateInterview `json:"interviews,omitempty"`
	AverageGradePercent float64              `json:"averageGradePercent,omitempty"`
}

type candidateValue struct {
	ID             int64     `json:"id"`
	LocationNumber string    `json:"locationNumber"`
	Name           string    `json:"name"`
	Description    string    `json:"description"`
	CreatedAt      time.Time `json:"createdAt"`
	UpdatedAt      time.Time `json:"updatedAt"`
}

type candidateInterviewName struct {
	ID             int64     `json:"id"`
	LocationNumber string    `json:"locationNumber"`
	Name           string    `json:"name"`
	Priority       int64     `json:"priority"`
	CreatedAt      time.Time `json:"createdAt"`
	UpdatedAt      time.Time `json:"updatedAt"`
}

type candidateInterview struct {
	ID                       int64                              `json:"id"`
	CandidateID              int64                              `json:"candidateId"`
	LocationNumber           string                             `json:"locationNumber"`
	InterviewerTimePunchName string                             `json:"interviewerTimePunchName"`
	InterviewType            string                             `json:"interviewType"`
	Notes                    string                             `json:"notes"`
	CreatedAt                time.Time                          `json:"createdAt"`
	Grades                   []candidateInterviewGrade          `json:"grades"`
	QuestionAnswers          []candidateInterviewQuestionAnswer `json:"questionAnswers,omitempty"`
}

type candidateInterviewQuestion struct {
	ID               int64     `json:"id"`
	LocationNumber   string    `json:"locationNumber"`
	InterviewNameID  int64     `json:"interviewNameId,omitempty"`
	InterviewName    string    `json:"interviewName,omitempty"`
	InterviewNameIDs []int64   `json:"interviewNameIds,omitempty"`
	InterviewNames   []string  `json:"interviewNames,omitempty"`
	Question         string    `json:"question"`
	ResponseType     string    `json:"responseType"`
	ResponseOptions  []string  `json:"responseOptions,omitempty"`
	CreatedAt        time.Time `json:"createdAt"`
	UpdatedAt        time.Time `json:"updatedAt"`
}

type candidateInterviewQuestionAnswer struct {
	ID           int64  `json:"id"`
	InterviewID  int64  `json:"interviewId"`
	QuestionID   int64  `json:"questionId"`
	QuestionText string `json:"questionText"`
	Answer       string `json:"answer"`
}

type candidateInterviewQuestionsResponse struct {
	Count     int                          `json:"count"`
	Questions []candidateInterviewQuestion `json:"questions"`
}

type candidateInterviewLink struct {
	Token                    string     `json:"token"`
	LocationNumber           string     `json:"locationNumber"`
	CandidateID              int64      `json:"candidateId"`
	InterviewerTimePunchName string     `json:"interviewerTimePunchName"`
	InterviewType            string     `json:"interviewType"`
	ScheduledAt              time.Time  `json:"scheduledAt"`
	Link                     string     `json:"link,omitempty"`
	ExpiresAt                time.Time  `json:"expiresAt"`
	UsedAt                   *time.Time `json:"usedAt,omitempty"`
	CreatedAt                time.Time  `json:"createdAt"`
}

type interviewCalendarEntry struct {
	Token                    string     `json:"token"`
	LocationNumber           string     `json:"locationNumber"`
	CandidateID              int64      `json:"candidateId"`
	CandidateFirstName       string     `json:"candidateFirstName"`
	CandidateLastName        string     `json:"candidateLastName"`
	InterviewerTimePunchName string     `json:"interviewerTimePunchName"`
	InterviewType            string     `json:"interviewType"`
	ScheduledAt              time.Time  `json:"scheduledAt"`
	UsedAt                   *time.Time `json:"usedAt,omitempty"`
	CreatedAt                time.Time  `json:"createdAt"`
}

type candidateInterviewGrade struct {
	ID          int64   `json:"id"`
	InterviewID int64   `json:"interviewId"`
	ValueID     int64   `json:"valueId"`
	ValueName   string  `json:"valueName"`
	LetterGrade string  `json:"letterGrade"`
	Comment     string  `json:"comment"`
	Score       float64 `json:"score"`
}

type server struct {
	store      *sqliteStore
	sessionTTL time.Duration
}

func DefaultConfigFromEnv() Config {
	return Config{
		Addr:          envOrDefault("API_ADDR", ":8080"),
		DBPath:        envOrDefault("AUTH_DB_PATH", "data.db"),
		AdminUsername: strings.TrimSpace(os.Getenv("ADMIN_USERNAME")),
		AdminPassword: os.Getenv("ADMIN_PASSWORD"),
		SessionTTL:    12 * time.Hour,
	}
}

func Run(ctx context.Context, cfg Config) error {
	if cfg.AdminUsername == "" || cfg.AdminPassword == "" {
		return errors.New("ADMIN_USERNAME and ADMIN_PASSWORD are required")
	}
	if cfg.SessionTTL <= 0 {
		cfg.SessionTTL = 12 * time.Hour
	}

	s := &server{
		store:      &sqliteStore{dbPath: cfg.DBPath},
		sessionTTL: cfg.SessionTTL,
	}

	if err := s.store.initSchema(ctx); err != nil {
		return fmt.Errorf("initialize schema: %w", err)
	}
	if err := s.store.ensureDefaultDepartmentsAndJobsForAllLocations(ctx); err != nil {
		return fmt.Errorf("ensure default departments and jobs: %w", err)
	}
	if err := s.store.ensureAdminUser(ctx, cfg.AdminUsername, cfg.AdminPassword); err != nil {
		return fmt.Errorf("ensure admin user: %w", err)
	}
	if err := ensurePaperworkDependenciesOnStartup(); err != nil {
		return fmt.Errorf("paperwork dependency preflight failed: %w", err)
	}
	mux := http.NewServeMux()
	mux.Handle("/api/health", http.HandlerFunc(s.health))
	mux.Handle("/api/auth/login", http.HandlerFunc(s.login))
	mux.Handle("/api/auth/team-login", http.HandlerFunc(s.teamLogin))
	mux.Handle("/api/auth/team-impersonate", middleware.Chain(http.HandlerFunc(s.teamImpersonate), s.requireAuthenticated, s.csrfProtect))
	mux.Handle("/api/auth/restaurant-impersonate", middleware.Chain(http.HandlerFunc(s.restaurantImpersonate), s.requireAuthenticated, s.csrfProtect))
	mux.Handle("/api/auth/me", middleware.Chain(http.HandlerFunc(s.me), s.requireAuthenticated))
	mux.Handle("/api/auth/csrf", middleware.Chain(http.HandlerFunc(s.csrfToken), s.requireAuthenticated))
	mux.Handle("/api/auth/logout", middleware.Chain(http.HandlerFunc(s.logout), s.requireAuthenticated, s.csrfProtect))
	mux.Handle("/api/admin/locations", middleware.Chain(http.HandlerFunc(s.locationsHandler), s.requireAuthenticated, s.csrfProtect))
	mux.Handle("/api/admin/locations/", middleware.Chain(http.HandlerFunc(s.locationByNumberHandler), s.requireAuthenticated, s.csrfProtect))
	mux.Handle("/api/public/employee-photo-upload/", http.HandlerFunc(s.publicEmployeePhotoUploadHandler))
	mux.Handle("/api/public/employee-paperwork/", http.HandlerFunc(s.publicEmployeePaperworkHandler))
	mux.Handle("/api/public/interview/", http.HandlerFunc(s.publicCandidateInterviewHandler))
	mux.Handle("/api/public/time-punch/", http.HandlerFunc(s.publicTimePunchHandler))
	mux.Handle("/api/public/time-off/", http.HandlerFunc(s.publicTimeOffHandler))
	mux.Handle("/api/public/uniform-order/", http.HandlerFunc(s.publicUniformOrderHandler))

	csp := strings.Join([]string{
		"default-src 'self'",
		"style-src 'self' https://fonts.googleapis.com 'unsafe-inline'",
		"font-src 'self' https://fonts.gstatic.com",
		"img-src 'self' data:",
		"script-src 'self'",
		"connect-src 'self'",
		"frame-ancestors 'none'",
	}, "; ")

	handler := middleware.Chain(
		mux,
		middleware.SecurityHeaders(middleware.SecurityHeadersConfig{ContentSecurityPolicy: csp}),
	)

	httpServer := &http.Server{
		Addr:              cfg.Addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		log.Printf("api listening on http://localhost%s", cfg.Addr)
		errCh <- httpServer.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdownCtx)
		return ctx.Err()
	case err := <-errCh:
		if err == nil || errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func (s *server) health(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *server) login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "username and password are required")
		return
	}

	user, hash, err := s.store.lookupUserByUsername(r.Context(), req.Username)
	if err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusUnauthorized, "invalid credentials")
			return
		}
		writeError(w, http.StatusInternalServerError, "authentication failed")
		return
	}

	if !security.VerifyPassword(req.Password, hash) {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	if userRoleOrDefault(user.Role, user.IsAdmin) == userRoleTeam {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	expires, err := s.createSessionForUser(r.Context(), user.ID, w)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "authentication failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"message": "authenticated", "expiresAt": expires.Format(time.RFC3339)})
}

func (s *server) teamLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req teamLoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.Token = strings.TrimSpace(req.Token)
	req.LocationNumber = strings.TrimSpace(req.LocationNumber)
	req.TimePunchName = strings.TrimSpace(req.TimePunchName)
	req.Pin = strings.TrimSpace(req.Pin)

	if req.Token != "" {
		if req.Pin == "" {
			writeError(w, http.StatusBadRequest, "pin is required")
			return
		}
		tokenRecord, err := s.store.getLocationTimePunchToken(r.Context(), req.Token)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid credentials")
			return
		}
		user, err := s.store.lookupTeamUserByLocationAndPIN(r.Context(), tokenRecord.LocationNumber, req.Pin)
		if err != nil {
			if errors.Is(err, errNotFound) {
				writeError(w, http.StatusUnauthorized, "invalid credentials")
				return
			}
			writeError(w, http.StatusInternalServerError, "authentication failed")
			return
		}
		expires, err := s.createSessionForUser(r.Context(), user.ID, w)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "authentication failed")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"message": "authenticated", "expiresAt": expires.Format(time.RFC3339)})
		return
	}

	if req.LocationNumber == "" || req.TimePunchName == "" || req.Pin == "" {
		writeError(w, http.StatusBadRequest, "location number, team member, and pin are required")
		return
	}

	if _, err := s.store.getLocationEmployee(r.Context(), req.LocationNumber, req.TimePunchName); err != nil {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	user, hash, err := s.store.lookupTeamUserByLocationAndTimePunch(r.Context(), req.LocationNumber, req.TimePunchName)
	if err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusUnauthorized, "invalid credentials")
			return
		}
		writeError(w, http.StatusInternalServerError, "authentication failed")
		return
	}
	if !security.VerifyPassword(req.Pin, hash) {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	expires, err := s.createSessionForUser(r.Context(), user.ID, w)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "authentication failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"message": "authenticated", "expiresAt": expires.Format(time.RFC3339)})
}

func (s *server) teamImpersonate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	user := userFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	role := userRoleOrDefault(user.Role, user.IsAdmin)
	if role == userRoleTeam {
		writeError(w, http.StatusForbidden, "admin access required")
		return
	}

	var req teamImpersonateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.LocationNumber = strings.TrimSpace(req.LocationNumber)
	req.TimePunchName = strings.TrimSpace(req.TimePunchName)
	if req.LocationNumber == "" || req.TimePunchName == "" {
		writeError(w, http.StatusBadRequest, "location number and team member are required")
		return
	}
	if !userCanAccessLocation(user, req.LocationNumber) {
		writeError(w, http.StatusForbidden, "location access denied")
		return
	}
	if _, err := s.store.getLocationEmployee(r.Context(), req.LocationNumber, req.TimePunchName); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusBadRequest, "employee not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to validate employee")
		return
	}
	teamUser, _, err := s.store.lookupTeamUserByLocationAndTimePunch(r.Context(), req.LocationNumber, req.TimePunchName)
	if err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusBadRequest, "team member does not have a clock-in pin yet")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load team member session")
		return
	}
	expires, err := s.createSessionForUser(r.Context(), teamUser.ID, w)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to create team member session")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"message":        "impersonation started",
		"expiresAt":      expires.Format(time.RFC3339),
		"locationNumber": req.LocationNumber,
		"timePunchName":  req.TimePunchName,
	})
}

func (s *server) restaurantImpersonate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	user := userFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	role := userRoleOrDefault(user.Role, user.IsAdmin)
	if role == userRoleTeam {
		writeError(w, http.StatusForbidden, "admin access required")
		return
	}

	var req restaurantImpersonateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.LocationNumber = strings.TrimSpace(req.LocationNumber)
	if req.LocationNumber == "" {
		writeError(w, http.StatusBadRequest, "location number is required")
		return
	}
	if !userCanAccessLocation(user, req.LocationNumber) {
		writeError(w, http.StatusForbidden, "location access denied")
		return
	}

	restaurantUser, _, err := s.store.lookupRestaurantUserByLocation(r.Context(), req.LocationNumber)
	if err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusBadRequest, "restaurant login is not configured for this location")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load restaurant session")
		return
	}
	expires, err := s.createSessionForUser(r.Context(), restaurantUser.ID, w)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to create restaurant session")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"message":        "impersonation started",
		"expiresAt":      expires.Format(time.RFC3339),
		"locationNumber": req.LocationNumber,
	})
}

func (s *server) me(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	user := userFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id":             user.ID,
		"username":       user.Username,
		"isAdmin":        user.IsAdmin,
		"role":           userRoleOrDefault(user.Role, user.IsAdmin),
		"locationNumber": user.LocationNumber,
		"timePunchName":  user.TimePunchName,
	})
}

func (s *server) csrfToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	sess := sessionFromContext(r.Context())
	if sess == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"csrfToken": sess.CSRFToken})
}

func (s *server) logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	sess := sessionFromContext(r.Context())
	if sess != nil {
		_ = s.store.deleteSession(r.Context(), sess.ID)
	}
	expireSessionCookie(w)
	writeJSON(w, http.StatusOK, map[string]string{"message": "signed out"})
}

func (s *server) createSessionForUser(ctx context.Context, userID int64, w http.ResponseWriter) (time.Time, error) {
	sessionID, err := randomToken(32)
	if err != nil {
		return time.Time{}, err
	}
	csrfToken, err := randomToken(32)
	if err != nil {
		return time.Time{}, err
	}
	expires := time.Now().UTC().Add(s.sessionTTL)
	if err := s.store.createSession(ctx, sessionID, userID, csrfToken, expires); err != nil {
		return time.Time{}, err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(s.sessionTTL.Seconds()),
		Expires:  expires,
	})
	return expires, nil
}

func (s *server) locationsHandler(w http.ResponseWriter, r *http.Request) {
	if !isAdminUser(r.Context()) {
		writeError(w, http.StatusForbidden, "admin access required")
		return
	}
	switch r.Method {
	case http.MethodGet:
		s.listLocations(w, r)
	case http.MethodPost:
		s.createLocation(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *server) locationByNumberHandler(w http.ResponseWriter, r *http.Request) {
	trimmed := strings.TrimPrefix(r.URL.Path, "/api/admin/locations/")
	trimmed = strings.Trim(trimmed, "/")
	if trimmed == "" {
		http.NotFound(w, r)
		return
	}
	parts := strings.Split(trimmed, "/")
	if len(parts) == 0 || strings.TrimSpace(parts[0]) == "" {
		http.NotFound(w, r)
		return
	}

	locationNumber, err := url.PathUnescape(parts[0])
	if err != nil || strings.TrimSpace(locationNumber) == "" {
		http.NotFound(w, r)
		return
	}
	if !userCanAccessLocation(userFromContext(r.Context()), locationNumber) {
		writeError(w, http.StatusForbidden, "location access denied")
		return
	}

	if len(parts) == 1 {
		switch r.Method {
		case http.MethodGet:
			s.getLocationByNumber(w, r, locationNumber)
			return
		case http.MethodPut:
			s.updateLocation(w, r, locationNumber)
			return
		case http.MethodDelete:
			s.deleteLocation(w, r, locationNumber)
			return
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
	}

	if len(parts) == 2 && parts[1] == "settings" {
		switch r.Method {
		case http.MethodGet:
			s.getLocationSettings(w, r, locationNumber)
			return
		case http.MethodPut:
			s.updateLocationSettings(w, r, locationNumber)
			return
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
	}

	if len(parts) == 2 && parts[1] == "candidate-values" {
		switch r.Method {
		case http.MethodGet:
			s.listLocationCandidateValues(w, r, locationNumber)
			return
		case http.MethodPost:
			s.createLocationCandidateValue(w, r, locationNumber)
			return
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
	}

	if len(parts) == 2 && parts[1] == "candidate-interview-names" {
		switch r.Method {
		case http.MethodGet:
			s.listLocationCandidateInterviewNames(w, r, locationNumber)
			return
		case http.MethodPost:
			s.createLocationCandidateInterviewName(w, r, locationNumber)
			return
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
	}

	if len(parts) == 2 && parts[1] == "candidate-interview-questions" {
		switch r.Method {
		case http.MethodGet:
			s.listLocationCandidateInterviewQuestions(w, r, locationNumber)
			return
		case http.MethodPost:
			s.createLocationCandidateInterviewQuestion(w, r, locationNumber)
			return
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
	}

	if len(parts) == 2 && parts[1] == "candidate-interview-calendar" {
		switch r.Method {
		case http.MethodGet:
			s.listLocationInterviewCalendar(w, r, locationNumber)
			return
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
	}

	if len(parts) == 3 && parts[1] == "candidate-interview-names" {
		nameID, err := strconv.ParseInt(strings.TrimSpace(parts[2]), 10, 64)
		if err != nil || nameID <= 0 {
			writeError(w, http.StatusBadRequest, "invalid interview type id")
			return
		}
		switch r.Method {
		case http.MethodPut:
			s.updateLocationCandidateInterviewName(w, r, locationNumber, nameID)
			return
		case http.MethodDelete:
			s.deleteLocationCandidateInterviewName(w, r, locationNumber, nameID)
			return
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
	}

	if len(parts) == 3 && parts[1] == "candidate-values" {
		valueID, err := strconv.ParseInt(strings.TrimSpace(parts[2]), 10, 64)
		if err != nil || valueID <= 0 {
			writeError(w, http.StatusBadRequest, "invalid candidate value id")
			return
		}
		switch r.Method {
		case http.MethodPut:
			s.updateLocationCandidateValue(w, r, locationNumber, valueID)
			return
		case http.MethodDelete:
			s.deleteLocationCandidateValue(w, r, locationNumber, valueID)
			return
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
	}

	if len(parts) == 3 && parts[1] == "candidate-interview-questions" {
		questionID, err := strconv.ParseInt(strings.TrimSpace(parts[2]), 10, 64)
		if err != nil || questionID <= 0 {
			writeError(w, http.StatusBadRequest, "invalid candidate interview question id")
			return
		}
		switch r.Method {
		case http.MethodPut:
			s.updateLocationCandidateInterviewQuestion(w, r, locationNumber, questionID)
			return
		case http.MethodDelete:
			s.deleteLocationCandidateInterviewQuestion(w, r, locationNumber, questionID)
			return
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
	}

	if len(parts) == 2 && parts[1] == "candidates" {
		switch r.Method {
		case http.MethodGet:
			s.listLocationCandidates(w, r, locationNumber)
			return
		case http.MethodPost:
			s.createLocationCandidate(w, r, locationNumber)
			return
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
	}

	if len(parts) == 3 && parts[1] == "candidates" {
		candidateID, err := strconv.ParseInt(strings.TrimSpace(parts[2]), 10, 64)
		if err != nil || candidateID <= 0 {
			writeError(w, http.StatusBadRequest, "invalid candidate id")
			return
		}
		switch r.Method {
		case http.MethodGet:
			s.getLocationCandidate(w, r, locationNumber, candidateID)
			return
		case http.MethodPut:
			s.updateLocationCandidateDecision(w, r, locationNumber, candidateID)
			return
		case http.MethodDelete:
			s.deleteLocationCandidate(w, r, locationNumber, candidateID)
			return
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
	}

	if len(parts) == 4 && parts[1] == "candidates" && parts[3] == "scorecard" {
		candidateID, err := strconv.ParseInt(strings.TrimSpace(parts[2]), 10, 64)
		if err != nil || candidateID <= 0 {
			writeError(w, http.StatusBadRequest, "invalid candidate id")
			return
		}
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.getLocationCandidateScorecard(w, r, locationNumber, candidateID)
		return
	}

	if len(parts) == 4 && parts[1] == "candidates" && parts[3] == "interviews" {
		if candidateID, err := strconv.ParseInt(strings.TrimSpace(parts[2]), 10, 64); err != nil || candidateID <= 0 {
			writeError(w, http.StatusBadRequest, "invalid candidate id")
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		writeError(w, http.StatusForbidden, "admin interview submission is disabled; use a generated interview link")
		return
	}

	if len(parts) == 4 && parts[1] == "candidates" && parts[3] == "interview-link" {
		candidateID, err := strconv.ParseInt(strings.TrimSpace(parts[2]), 10, 64)
		if err != nil || candidateID <= 0 {
			writeError(w, http.StatusBadRequest, "invalid candidate id")
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.createLocationCandidateInterviewLink(w, r, locationNumber, candidateID)
		return
	}

	if len(parts) == 4 && parts[1] == "candidates" && parts[3] == "interview-links" {
		candidateID, err := strconv.ParseInt(strings.TrimSpace(parts[2]), 10, 64)
		if err != nil || candidateID <= 0 {
			writeError(w, http.StatusBadRequest, "invalid candidate id")
			return
		}
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.listLocationCandidateInterviewLinks(w, r, locationNumber, candidateID)
		return
	}

	if len(parts) == 5 && parts[1] == "candidates" && parts[3] == "interview-links" {
		candidateID, err := strconv.ParseInt(strings.TrimSpace(parts[2]), 10, 64)
		if err != nil || candidateID <= 0 {
			writeError(w, http.StatusBadRequest, "invalid candidate id")
			return
		}
		token := strings.TrimSpace(parts[4])
		if token == "" {
			writeError(w, http.StatusBadRequest, "invalid interview token")
			return
		}
		switch r.Method {
		case http.MethodGet:
			s.getLocationCandidateInterviewLink(w, r, locationNumber, candidateID, token)
			return
		case http.MethodDelete:
			s.deleteLocationCandidateInterviewLink(w, r, locationNumber, candidateID, token)
			return
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
	}

	if len(parts) == 2 && parts[1] == "employees" {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.listLocationEmployees(w, r, locationNumber)
		return
	}

	if len(parts) == 3 && parts[1] == "employees" && parts[2] == "archived" {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.listArchivedLocationEmployees(w, r, locationNumber)
		return
	}

	if len(parts) == 2 && parts[1] == "business-days" {
		switch r.Method {
		case http.MethodGet:
			s.listLocationBusinessDays(w, r, locationNumber)
			return
		case http.MethodPost:
			s.createLocationBusinessDay(w, r, locationNumber)
			return
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
	}

	if len(parts) == 2 && parts[1] == "uniform-items" {
		switch r.Method {
		case http.MethodGet:
			s.listLocationUniformItems(w, r, locationNumber)
			return
		case http.MethodPost:
			s.createLocationUniformItem(w, r, locationNumber)
			return
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
	}

	if len(parts) == 3 && parts[1] == "uniform-items" {
		itemID, err := strconv.ParseInt(strings.TrimSpace(parts[2]), 10, 64)
		if err != nil || itemID <= 0 {
			writeError(w, http.StatusBadRequest, "invalid uniform item id")
			return
		}
		switch r.Method {
		case http.MethodGet:
			s.getLocationUniformItem(w, r, locationNumber, itemID)
		case http.MethodPut:
			s.updateLocationUniformItem(w, r, locationNumber, itemID)
		case http.MethodDelete:
			s.deleteLocationUniformItem(w, r, locationNumber, itemID)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
		return
	}

	if len(parts) == 4 && parts[1] == "uniform-items" && parts[3] == "images" {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		itemID, err := strconv.ParseInt(strings.TrimSpace(parts[2]), 10, 64)
		if err != nil || itemID <= 0 {
			writeError(w, http.StatusBadRequest, "invalid uniform item id")
			return
		}
		s.addLocationUniformItemImages(w, r, locationNumber, itemID)
		return
	}

	if len(parts) == 5 && parts[1] == "uniform-items" && parts[3] == "images" {
		if r.Method != http.MethodDelete {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		itemID, err := strconv.ParseInt(strings.TrimSpace(parts[2]), 10, 64)
		if err != nil || itemID <= 0 {
			writeError(w, http.StatusBadRequest, "invalid uniform item id")
			return
		}
		imageID, err := strconv.ParseInt(strings.TrimSpace(parts[4]), 10, 64)
		if err != nil || imageID <= 0 {
			writeError(w, http.StatusBadRequest, "invalid uniform image id")
			return
		}
		s.deleteLocationUniformItemImage(w, r, locationNumber, itemID, imageID)
		return
	}

	if len(parts) == 6 && parts[1] == "uniform-items" && parts[3] == "images" && parts[5] == "move" {
		if r.Method != http.MethodPut {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		itemID, err := strconv.ParseInt(strings.TrimSpace(parts[2]), 10, 64)
		if err != nil || itemID <= 0 {
			writeError(w, http.StatusBadRequest, "invalid uniform item id")
			return
		}
		imageID, err := strconv.ParseInt(strings.TrimSpace(parts[4]), 10, 64)
		if err != nil || imageID <= 0 {
			writeError(w, http.StatusBadRequest, "invalid uniform image id")
			return
		}
		s.moveLocationUniformItemImage(w, r, locationNumber, itemID, imageID)
		return
	}

	if len(parts) == 2 && parts[1] == "uniform-orders" {
		switch r.Method {
		case http.MethodGet:
			s.listLocationUniformOrders(w, r, locationNumber)
			return
		case http.MethodPost:
			s.createLocationUniformOrder(w, r, locationNumber)
			return
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
	}

	if len(parts) == 3 && parts[1] == "uniform-orders" {
		orderID, err := strconv.ParseInt(strings.TrimSpace(parts[2]), 10, 64)
		if err != nil || orderID <= 0 {
			writeError(w, http.StatusBadRequest, "invalid uniform order id")
			return
		}
		switch r.Method {
		case http.MethodPut:
			s.archiveLocationUniformOrder(w, r, locationNumber, orderID)
			return
		case http.MethodDelete:
			s.deleteArchivedLocationUniformOrder(w, r, locationNumber, orderID)
			return
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
	}

	if len(parts) == 5 && parts[1] == "uniform-orders" && parts[3] == "lines" {
		orderID, err := strconv.ParseInt(strings.TrimSpace(parts[2]), 10, 64)
		if err != nil || orderID <= 0 {
			writeError(w, http.StatusBadRequest, "invalid uniform order id")
			return
		}
		lineID, err := strconv.ParseInt(strings.TrimSpace(parts[4]), 10, 64)
		if err != nil || lineID <= 0 {
			writeError(w, http.StatusBadRequest, "invalid uniform order line id")
			return
		}
		if r.Method != http.MethodPut {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.updateLocationUniformOrderLineSettlement(w, r, locationNumber, orderID, lineID)
		return
	}

	if len(parts) == 3 && parts[1] == "uniform-order" && parts[2] == "link" {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.getLocationUniformOrderLink(w, r, locationNumber)
		return
	}

	if len(parts) == 3 && parts[1] == "business-days" {
		dateValue, err := url.PathUnescape(parts[2])
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid business date")
			return
		}
		dateValue = strings.TrimSpace(dateValue)
		if err := validateBusinessDateString(dateValue); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		switch r.Method {
		case http.MethodGet:
			s.getOrCreateLocationBusinessDay(w, r, locationNumber, dateValue)
			return
		case http.MethodPut:
			s.updateLocationBusinessDay(w, r, locationNumber, dateValue)
			return
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
	}

	if len(parts) == 2 && parts[1] == "time-punch" {
		switch r.Method {
		case http.MethodGet:
			s.listLocationTimePunchEntries(w, r, locationNumber)
			return
		case http.MethodPost:
			s.createLocationTimePunchEntry(w, r, locationNumber)
			return
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
	}

	if len(parts) == 2 && parts[1] == "time-off" {
		switch r.Method {
		case http.MethodGet:
			s.listLocationTimeOffRequests(w, r, locationNumber)
			return
		case http.MethodPost:
			s.createLocationTimeOffRequest(w, r, locationNumber)
			return
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		return
	}

	if len(parts) == 2 && parts[1] == "departments" {
		switch r.Method {
		case http.MethodGet:
			s.listLocationDepartments(w, r, locationNumber)
			return
		case http.MethodPost:
			s.createLocationDepartment(w, r, locationNumber)
			return
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
	}

	if len(parts) == 2 && parts[1] == "jobs" {
		switch r.Method {
		case http.MethodGet:
			s.listLocationJobs(w, r, locationNumber)
			return
		case http.MethodPost:
			s.createLocationJob(w, r, locationNumber)
			return
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
	}

	if len(parts) == 3 && parts[1] == "jobs" {
		jobID, err := strconv.ParseInt(strings.TrimSpace(parts[2]), 10, 64)
		if err != nil || jobID <= 0 {
			writeError(w, http.StatusBadRequest, "invalid pay band id")
			return
		}
		if r.Method != http.MethodPut {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.updateLocationJob(w, r, locationNumber, jobID)
		return
	}

	if len(parts) == 2 && parts[1] == "pay-bands" {
		switch r.Method {
		case http.MethodGet:
			s.listLocationJobs(w, r, locationNumber)
			return
		case http.MethodPost:
			s.createLocationJob(w, r, locationNumber)
			return
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
	}

	if len(parts) == 4 && parts[1] == "jobs" && parts[3] == "departments" {
		if r.Method != http.MethodPut {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		jobID, err := strconv.ParseInt(strings.TrimSpace(parts[2]), 10, 64)
		if err != nil || jobID <= 0 {
			writeError(w, http.StatusBadRequest, "invalid job id")
			return
		}
		s.assignLocationJobDepartments(w, r, locationNumber, jobID)
		return
	}

	if len(parts) == 3 && parts[1] == "time-punch" && parts[2] == "link" {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.getLocationTimePunchLink(w, r, locationNumber)
		return
	}

	if len(parts) == 3 && parts[1] == "time-off" && parts[2] == "link" {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.getLocationTimeOffLink(w, r, locationNumber)
		return
	}

	if len(parts) == 4 && parts[1] == "time-punch" && parts[3] == "archive" {
		if r.Method != http.MethodPut {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		entryID, err := strconv.ParseInt(strings.TrimSpace(parts[2]), 10, 64)
		if err != nil || entryID <= 0 {
			writeError(w, http.StatusBadRequest, "invalid time punch entry id")
			return
		}
		s.archiveLocationTimePunchEntry(w, r, locationNumber, entryID)
		return
	}

	if len(parts) == 3 && parts[1] == "time-punch" {
		if r.Method != http.MethodDelete {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		entryID, err := strconv.ParseInt(strings.TrimSpace(parts[2]), 10, 64)
		if err != nil || entryID <= 0 {
			writeError(w, http.StatusBadRequest, "invalid time punch entry id")
			return
		}
		s.deleteLocationTimePunchEntry(w, r, locationNumber, entryID)
		return
	}

	if len(parts) == 3 && parts[1] == "time-off" {
		if r.Method != http.MethodPut {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		requestID, err := strconv.ParseInt(strings.TrimSpace(parts[2]), 10, 64)
		if err != nil || requestID <= 0 {
			writeError(w, http.StatusBadRequest, "invalid time off request id")
			return
		}
		s.archiveLocationTimeOffRequest(w, r, locationNumber, requestID)
		return
	}

	if len(parts) == 3 && parts[1] == "employees" && parts[2] == "import" {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.importLocationEmployees(w, r, locationNumber)
		return
	}

	if len(parts) == 3 && parts[1] == "employees" {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		timePunchName, err := url.PathUnescape(parts[2])
		if err != nil || strings.TrimSpace(timePunchName) == "" {
			writeError(w, http.StatusBadRequest, "invalid employee identifier")
			return
		}
		s.getLocationEmployee(w, r, locationNumber, timePunchName)
		return
	}

	if len(parts) == 4 && parts[1] == "employees" && parts[2] == "archived" {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		timePunchName, err := url.PathUnescape(parts[3])
		if err != nil || strings.TrimSpace(timePunchName) == "" {
			writeError(w, http.StatusBadRequest, "invalid employee identifier")
			return
		}
		s.getArchivedLocationEmployee(w, r, locationNumber, timePunchName)
		return
	}

	if len(parts) == 4 && parts[1] == "employees" && parts[3] == "department" {
		if r.Method != http.MethodPut {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		timePunchName, err := url.PathUnescape(parts[2])
		if err != nil || strings.TrimSpace(timePunchName) == "" {
			writeError(w, http.StatusBadRequest, "invalid employee identifier")
			return
		}
		s.updateEmployeeDepartment(w, r, locationNumber, timePunchName)
		return
	}

	if len(parts) == 4 && parts[1] == "employees" && parts[3] == "job" {
		if r.Method != http.MethodPut {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		timePunchName, err := url.PathUnescape(parts[2])
		if err != nil || strings.TrimSpace(timePunchName) == "" {
			writeError(w, http.StatusBadRequest, "invalid employee identifier")
			return
		}
		s.updateEmployeeJob(w, r, locationNumber, timePunchName)
		return
	}

	if len(parts) == 4 && parts[1] == "employees" && parts[3] == "pay-band" {
		if r.Method != http.MethodPut {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		timePunchName, err := url.PathUnescape(parts[2])
		if err != nil || strings.TrimSpace(timePunchName) == "" {
			writeError(w, http.StatusBadRequest, "invalid employee identifier")
			return
		}
		s.updateEmployeePayBand(w, r, locationNumber, timePunchName)
		return
	}

	if len(parts) == 4 && parts[1] == "employees" && parts[3] == "additional-compensations" {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		timePunchName, err := url.PathUnescape(parts[2])
		if err != nil || strings.TrimSpace(timePunchName) == "" {
			writeError(w, http.StatusBadRequest, "invalid employee identifier")
			return
		}
		s.listEmployeeAdditionalCompensations(w, r, locationNumber, timePunchName)
		return
	}

	if len(parts) == 5 && parts[1] == "employees" && parts[3] == "additional-compensations" && parts[4] == "add" {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		timePunchName, err := url.PathUnescape(parts[2])
		if err != nil || strings.TrimSpace(timePunchName) == "" {
			writeError(w, http.StatusBadRequest, "invalid employee identifier")
			return
		}
		s.addEmployeeAdditionalCompensation(w, r, locationNumber, timePunchName)
		return
	}

	if len(parts) == 6 && parts[1] == "employees" && parts[3] == "additional-compensations" && parts[5] == "delete" {
		if r.Method != http.MethodDelete {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		timePunchName, err := url.PathUnescape(parts[2])
		if err != nil || strings.TrimSpace(timePunchName) == "" {
			writeError(w, http.StatusBadRequest, "invalid employee identifier")
			return
		}
		compID, err := strconv.ParseInt(strings.TrimSpace(parts[4]), 10, 64)
		if err != nil || compID <= 0 {
			writeError(w, http.StatusBadRequest, "invalid compensation id")
			return
		}
		s.deleteEmployeeAdditionalCompensation(w, r, locationNumber, timePunchName, compID)
		return
	}

	if len(parts) == 4 && parts[1] == "employees" && parts[3] == "clock-in-pin" {
		if r.Method != http.MethodPut {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		timePunchName, err := url.PathUnescape(parts[2])
		if err != nil || strings.TrimSpace(timePunchName) == "" {
			writeError(w, http.StatusBadRequest, "invalid employee identifier")
			return
		}
		s.updateLocationEmployeeClockInPIN(w, r, locationNumber, timePunchName)
		return
	}

	if len(parts) == 4 && parts[1] == "employees" && parts[3] == "terminate" {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		timePunchName, err := url.PathUnescape(parts[2])
		if err != nil || strings.TrimSpace(timePunchName) == "" {
			writeError(w, http.StatusBadRequest, "invalid employee identifier")
			return
		}
		s.terminateLocationEmployee(w, r, locationNumber, timePunchName)
		return
	}

	if len(parts) == 4 && parts[1] == "employees" && parts[3] == "details" {
		if r.Method != http.MethodPut {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		timePunchName, err := url.PathUnescape(parts[2])
		if err != nil || strings.TrimSpace(timePunchName) == "" {
			writeError(w, http.StatusBadRequest, "invalid employee identifier")
			return
		}
		s.updateLocationEmployeeDetails(w, r, locationNumber, timePunchName)
		return
	}

	if len(parts) == 4 && parts[1] == "employees" && parts[3] == "scorecards" {
		timePunchName, err := url.PathUnescape(parts[2])
		if err != nil || strings.TrimSpace(timePunchName) == "" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.listEmployeeCandidateScorecards(w, r, locationNumber, timePunchName)
		return
	}

	if len(parts) == 4 && parts[1] == "employees" && parts[3] == "i9" {
		timePunchName, err := url.PathUnescape(parts[2])
		if err != nil || strings.TrimSpace(timePunchName) == "" {
			writeError(w, http.StatusBadRequest, "invalid employee identifier")
			return
		}
		switch r.Method {
		case http.MethodGet:
			s.getEmployeeI9(w, r, locationNumber, timePunchName)
			return
		case http.MethodPost:
			s.uploadEmployeeI9(w, r, locationNumber, timePunchName)
			return
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
	}

	if len(parts) == 4 && parts[1] == "employees" && parts[3] == "w4" {
		timePunchName, err := url.PathUnescape(parts[2])
		if err != nil || strings.TrimSpace(timePunchName) == "" {
			writeError(w, http.StatusBadRequest, "invalid employee identifier")
			return
		}
		switch r.Method {
		case http.MethodGet:
			s.getEmployeeW4(w, r, locationNumber, timePunchName)
			return
		case http.MethodPost:
			s.uploadEmployeeW4(w, r, locationNumber, timePunchName)
			return
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
	}

	if len(parts) == 5 && parts[1] == "employees" && parts[3] == "w4" && parts[4] == "file" {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		timePunchName, err := url.PathUnescape(parts[2])
		if err != nil || strings.TrimSpace(timePunchName) == "" {
			writeError(w, http.StatusBadRequest, "invalid employee identifier")
			return
		}
		s.getEmployeeW4File(w, r, locationNumber, timePunchName)
		return
	}

	if len(parts) == 5 && parts[1] == "employees" && parts[3] == "i9" && parts[4] == "file" {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		timePunchName, err := url.PathUnescape(parts[2])
		if err != nil || strings.TrimSpace(timePunchName) == "" {
			writeError(w, http.StatusBadRequest, "invalid employee identifier")
			return
		}
		s.getEmployeeI9File(w, r, locationNumber, timePunchName)
		return
	}

	if len(parts) == 5 && parts[1] == "employees" && parts[3] == "i9" && parts[4] == "documents" {
		timePunchName, err := url.PathUnescape(parts[2])
		if err != nil || strings.TrimSpace(timePunchName) == "" {
			writeError(w, http.StatusBadRequest, "invalid employee identifier")
			return
		}
		if r.Method == http.MethodGet {
			s.listEmployeeI9Documents(w, r, locationNumber, timePunchName)
			return
		}
		if r.Method == http.MethodPost {
			s.uploadEmployeeI9Document(w, r, locationNumber, timePunchName)
			return
		}
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if len(parts) == 6 && parts[1] == "employees" && parts[3] == "i9" && parts[4] == "documents" {
		timePunchName, err := url.PathUnescape(parts[2])
		if err != nil || strings.TrimSpace(timePunchName) == "" {
			writeError(w, http.StatusBadRequest, "invalid employee identifier")
			return
		}
		docID, err := strconv.ParseInt(strings.TrimSpace(parts[5]), 10, 64)
		if err != nil || docID <= 0 {
			writeError(w, http.StatusBadRequest, "invalid i9 document id")
			return
		}
		switch r.Method {
		case http.MethodGet:
			s.getEmployeeI9DocumentFile(w, r, locationNumber, timePunchName, docID)
		case http.MethodDelete:
			s.deleteEmployeeI9Document(w, r, locationNumber, timePunchName, docID)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
		return
	}

	if len(parts) == 5 && parts[1] == "employees" && parts[2] == "archived" && parts[4] == "i9" {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		timePunchName, err := url.PathUnescape(parts[3])
		if err != nil || strings.TrimSpace(timePunchName) == "" {
			writeError(w, http.StatusBadRequest, "invalid employee identifier")
			return
		}
		s.getArchivedEmployeeI9(w, r, locationNumber, timePunchName)
		return
	}

	if len(parts) == 5 && parts[1] == "employees" && parts[2] == "archived" && parts[4] == "w4" {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		timePunchName, err := url.PathUnescape(parts[3])
		if err != nil || strings.TrimSpace(timePunchName) == "" {
			writeError(w, http.StatusBadRequest, "invalid employee identifier")
			return
		}
		s.getArchivedEmployeeW4(w, r, locationNumber, timePunchName)
		return
	}

	if len(parts) == 6 && parts[1] == "employees" && parts[2] == "archived" && parts[4] == "w4" && parts[5] == "file" {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		timePunchName, err := url.PathUnescape(parts[3])
		if err != nil || strings.TrimSpace(timePunchName) == "" {
			writeError(w, http.StatusBadRequest, "invalid employee identifier")
			return
		}
		s.getArchivedEmployeeW4File(w, r, locationNumber, timePunchName)
		return
	}

	if len(parts) == 6 && parts[1] == "employees" && parts[2] == "archived" && parts[4] == "i9" && parts[5] == "file" {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		timePunchName, err := url.PathUnescape(parts[3])
		if err != nil || strings.TrimSpace(timePunchName) == "" {
			writeError(w, http.StatusBadRequest, "invalid employee identifier")
			return
		}
		s.getArchivedEmployeeI9File(w, r, locationNumber, timePunchName)
		return
	}

	if len(parts) == 7 && parts[1] == "employees" && parts[2] == "archived" && parts[4] == "i9" && parts[5] == "documents" {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		timePunchName, err := url.PathUnescape(parts[3])
		if err != nil || strings.TrimSpace(timePunchName) == "" {
			writeError(w, http.StatusBadRequest, "invalid employee identifier")
			return
		}
		docID, err := strconv.ParseInt(strings.TrimSpace(parts[6]), 10, 64)
		if err != nil || docID <= 0 {
			writeError(w, http.StatusBadRequest, "invalid i9 document id")
			return
		}
		s.getArchivedEmployeeI9DocumentFile(w, r, locationNumber, timePunchName, docID)
		return
	}

	if len(parts) == 4 && parts[1] == "employees" && parts[3] == "photo" {
		timePunchName, err := url.PathUnescape(parts[2])
		if err != nil || strings.TrimSpace(timePunchName) == "" {
			writeError(w, http.StatusBadRequest, "invalid employee identifier")
			return
		}
		switch r.Method {
		case http.MethodGet:
			s.getEmployeePhoto(w, r, locationNumber, timePunchName)
			return
		case http.MethodPost:
			s.uploadEmployeePhoto(w, r, locationNumber, timePunchName)
			return
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
	}

	if len(parts) == 4 && parts[1] == "employees" && parts[3] == "photo-link" {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		timePunchName, err := url.PathUnescape(parts[2])
		if err != nil || strings.TrimSpace(timePunchName) == "" {
			writeError(w, http.StatusBadRequest, "invalid employee identifier")
			return
		}
		s.createEmployeePhotoLink(w, r, locationNumber, timePunchName)
		return
	}

	if len(parts) == 4 && parts[1] == "employees" && parts[3] == "paperwork-link" {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		timePunchName, err := url.PathUnescape(parts[2])
		if err != nil || strings.TrimSpace(timePunchName) == "" {
			writeError(w, http.StatusBadRequest, "invalid employee identifier")
			return
		}
		s.createEmployeePaperworkLink(w, r, locationNumber, timePunchName)
		return
	}

	if len(parts) == 4 && parts[1] == "employees" && parts[2] == "birthdates" && parts[3] == "import" {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.importLocationBirthdates(w, r, locationNumber)
		return
	}

	http.NotFound(w, r)
}

func (s *server) publicEmployeePhotoUploadHandler(w http.ResponseWriter, r *http.Request) {
	trimmed := strings.TrimPrefix(r.URL.Path, "/api/public/employee-photo-upload/")
	trimmed = strings.Trim(trimmed, "/")
	if trimmed == "" {
		http.NotFound(w, r)
		return
	}
	token := strings.TrimSpace(trimmed)
	record, err := s.store.getEmployeePhotoToken(r.Context(), token)
	if err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "invalid or expired upload link")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to validate upload link")
		return
	}

	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{
			"locationNumber": record.LocationNum,
			"timePunchName":  record.TimePunchName,
			"expiresAt":      record.ExpiresAt.Format(time.RFC3339),
		})
	case http.MethodPost:
		data, mime, err := parseUploadedPhoto(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := withSQLiteRetry(func() error {
			return s.store.updateEmployeePhoto(r.Context(), record.LocationNum, record.TimePunchName, data, mime)
		}); err != nil {
			writeError(w, http.StatusInternalServerError, "unable to persist photo: "+err.Error())
			return
		}
		_ = s.store.markEmployeePhotoTokenUsed(r.Context(), token)
		writeJSON(w, http.StatusOK, map[string]string{"message": "photo uploaded"})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *server) publicEmployeePaperworkHandler(w http.ResponseWriter, r *http.Request) {
	trimmed := strings.TrimPrefix(r.URL.Path, "/api/public/employee-paperwork/")
	trimmed = strings.Trim(trimmed, "/")
	if trimmed == "" {
		http.NotFound(w, r)
		return
	}
	parts := strings.Split(trimmed, "/")
	locationNumber := ""
	timePunchName := ""
	expiresAt := ""
	routeParts := []string{}
	resolveTokenRecord := func(token string) (*employeePaperworkToken, error) {
		record, err := s.store.getEmployeePaperworkToken(r.Context(), token)
		if err != nil {
			if errors.Is(err, errNotFound) {
				return nil, errNotFound
			}
			return nil, err
		}
		return record, nil
	}
	if len(parts) >= 2 && strings.EqualFold(strings.TrimSpace(parts[1]), "packets") {
		token := strings.TrimSpace(parts[0])
		record, err := resolveTokenRecord(token)
		if err != nil {
			if errors.Is(err, errNotFound) {
				writeError(w, http.StatusNotFound, "invalid or expired paperwork link")
				return
			}
			writeError(w, http.StatusInternalServerError, "unable to validate paperwork link")
			return
		}
		locationNumber = record.LocationNum
		timePunchName = record.TimePunchName
		expiresAt = record.ExpiresAt.Format(time.RFC3339)
		routeParts = append(routeParts, parts[1:]...)
	} else if len(parts) >= 3 && strings.EqualFold(strings.TrimSpace(parts[2]), "packets") {
		var err error
		locationNumber, err = url.PathUnescape(strings.TrimSpace(parts[0]))
		if err != nil || strings.TrimSpace(locationNumber) == "" {
			writeError(w, http.StatusBadRequest, "invalid location")
			return
		}
		timePunchName, err = url.PathUnescape(strings.TrimSpace(parts[1]))
		if err != nil || strings.TrimSpace(timePunchName) == "" {
			writeError(w, http.StatusBadRequest, "invalid employee")
			return
		}
		routeParts = append(routeParts, parts[2:]...)
	} else if len(parts) == 1 {
		token := strings.TrimSpace(parts[0])
		record, err := s.store.getEmployeePaperworkToken(r.Context(), token)
		if err != nil {
			if errors.Is(err, errNotFound) {
				writeError(w, http.StatusNotFound, "invalid or expired paperwork link")
				return
			}
			writeError(w, http.StatusInternalServerError, "unable to validate paperwork link")
			return
		}
		locationNumber = record.LocationNum
		timePunchName = record.TimePunchName
		expiresAt = record.ExpiresAt.Format(time.RFC3339)
	} else if len(parts) == 2 {
		var err error
		locationNumber, err = url.PathUnescape(strings.TrimSpace(parts[0]))
		if err != nil || strings.TrimSpace(locationNumber) == "" {
			writeError(w, http.StatusBadRequest, "invalid location")
			return
		}
		timePunchName, err = url.PathUnescape(strings.TrimSpace(parts[1]))
		if err != nil || strings.TrimSpace(timePunchName) == "" {
			writeError(w, http.StatusBadRequest, "invalid employee")
			return
		}
	} else {
		http.NotFound(w, r)
		return
	}
	if len(routeParts) > 0 {
		s.publicEmployeePaperworkPacketRoutes(w, r, locationNumber, timePunchName, routeParts)
		return
	}
	employeeRecord, err := s.store.getLocationEmployee(r.Context(), locationNumber, timePunchName)
	if err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "employee not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load employee")
		return
	}
	submitted, err := s.store.hasEmployeePaperworkSubmission(r.Context(), locationNumber, timePunchName)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to validate paperwork status")
		return
	}
	// New-hire links remain one-time after first full submission.
	// Active employees must be allowed to reopen paperwork for updates.
	if submitted && !employeeRecord.HasCompletedPaperwork {
		writeError(w, http.StatusGone, "paperwork link has already been used")
		return
	}

	switch r.Method {
	case http.MethodGet:
		loc, err := s.store.getLocationByNumber(r.Context(), locationNumber)
		if err != nil {
			if errors.Is(err, errNotFound) {
				writeError(w, http.StatusNotFound, "location not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "unable to load location")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"locationNumber": locationNumber,
			"locationName":   loc.Name,
			"timePunchName":  timePunchName,
			"firstName":      employeeRecord.FirstName,
			"lastName":       employeeRecord.LastName,
			"expiresAt":      expiresAt,
		})
	case http.MethodPost:
		contentType := strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Type")))
		isMultipart := strings.HasPrefix(contentType, "multipart/form-data")
		if isMultipart {
			if err := r.ParseMultipartForm(36 << 20); err != nil {
				writeError(w, http.StatusBadRequest, "invalid paperwork form")
				return
			}
		} else {
			if err := r.ParseForm(); err != nil {
				writeError(w, http.StatusBadRequest, "invalid paperwork form")
				return
			}
		}
		s.applyPaperworkDefaults(r.Context(), locationNumber, r.PostForm)
		employeePatch, err := paperworkEmployeePatchFromForm(employeeRecord, r.PostForm)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		target := strings.ToLower(strings.TrimSpace(r.PostForm.Get("paperwork_target")))
		saveI9 := target == "" || target == "i9" || target == "both" || target == "all"
		saveW4 := target == "w4" || target == "both" || target == "all"
		if !saveI9 && !saveW4 {
			writeError(w, http.StatusBadRequest, "invalid paperwork target")
			return
		}
		if normalizedState := normalizeUSStateCode(r.PostForm.Get("state")); normalizedState != "" {
			r.PostForm.Set("state", normalizedState)
		}
		attested := parseBoolQueryValue(r.PostForm.Get("employee_esign_attestation"))
		if !attested {
			writeError(w, http.StatusBadRequest, "you must confirm electronic signature attestation")
			return
		}
		drawnSignature := strings.TrimSpace(r.PostForm.Get("employee_signature_drawn"))
		if drawnSignature == "" {
			writeError(w, http.StatusBadRequest, "drawn signature is required")
			return
		}
		signatureImageData, _, err := parseDataURLBinary(drawnSignature, []string{"image/png", "image/jpeg", "image/webp"}, 2<<20)
		if err != nil {
			writeError(w, http.StatusBadRequest, "drawn signature is required")
			return
		}
		savedAny := false
		if saveI9 {
			if !isMultipart {
				writeError(w, http.StatusBadRequest, "upload at least one i-9 supporting document")
				return
			}
			i9Uploads, err := collectI9SupportingDocumentsFromRequest(r)
			if err != nil {
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}
			if err := validateI9DocumentRequirements(i9Uploads); err != nil {
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}
			applyI9DocumentValuesToForm(r.PostForm, i9Uploads)
			i9Data, i9Err := generateFilledI9PDF(r.PostForm)
			if i9Err != nil {
				writeError(w, http.StatusBadRequest, i9Err.Error())
				return
			}
			i9Data, err = stampDrawnSignatureOnPDF(i9Data, signatureImageData, i9EmployeeSignaturePlacement)
			if err != nil {
				writeError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if err := withSQLiteRetry(func() error {
				return s.store.upsertEmployeeI9Form(r.Context(), locationNumber, timePunchName, i9Data, "application/pdf", "i9-filled.pdf")
			}); err != nil {
				writeError(w, http.StatusInternalServerError, "unable to persist i9 form")
				return
			}
			if err := withSQLiteRetry(func() error {
				return s.store.deleteEmployeeI9DocumentsForEmployee(r.Context(), locationNumber, timePunchName)
			}); err != nil {
				writeError(w, http.StatusInternalServerError, "unable to reset i9 documents")
				return
			}
			for _, upload := range i9Uploads {
				current := upload
				if err := withSQLiteRetry(func() error {
					return s.store.addEmployeeI9Document(
						r.Context(),
						locationNumber,
						timePunchName,
						current.ListType,
						current.DocumentTitle,
						current.IssuingAuthority,
						current.DocumentNumber,
						current.ExpirationDate,
						current.Data,
						current.Mime,
						current.FileName,
					)
				}); err != nil {
					writeError(w, http.StatusInternalServerError, "unable to persist i9 supporting document")
					return
				}
			}
			savedAny = true
		}
		if saveW4 {
			if err := normalizeW4DollarFields(r.PostForm); err != nil {
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}
			w4Data, w4Err := generateFilledW4PDF(r.PostForm)
			if w4Err != nil {
				writeError(w, http.StatusBadRequest, w4Err.Error())
				return
			}
			w4Data, err = stampDrawnSignatureOnPDF(w4Data, signatureImageData, w4EmployeeSignaturePlacement)
			if err != nil {
				writeError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if err := withSQLiteRetry(func() error {
				return s.store.upsertEmployeeW4Form(r.Context(), locationNumber, timePunchName, w4Data, "application/pdf", "w4-filled.pdf")
			}); err != nil {
				writeError(w, http.StatusInternalServerError, "unable to persist w4 form")
				return
			}
			savedAny = true
		}
		signatureFileName := "employee-signature.png"
		signatureMime := "image/png"
		if len(signatureImageData) > 0 {
			// Keep original format if provided by the browser.
			if len(signatureImageData) >= 12 && string(signatureImageData[0:4]) == "RIFF" && string(signatureImageData[8:12]) == "WEBP" {
				signatureFileName = "employee-signature.webp"
				signatureMime = "image/webp"
			} else if len(signatureImageData) >= 3 && signatureImageData[0] == 0xFF && signatureImageData[1] == 0xD8 && signatureImageData[2] == 0xFF {
				signatureFileName = "employee-signature.jpg"
				signatureMime = "image/jpeg"
			}
		}
		if err := withSQLiteRetry(func() error {
			return s.store.deleteEmployeeI9DocumentsByListType(r.Context(), locationNumber, timePunchName, "signature")
		}); err != nil {
			writeError(w, http.StatusInternalServerError, "unable to update signature copy")
			return
		}
		if err := withSQLiteRetry(func() error {
			return s.store.addEmployeeI9Document(
				r.Context(),
				locationNumber,
				timePunchName,
				"signature",
				"Employee Digital Signature",
				"Electronic Signature",
				"",
				"",
				signatureImageData,
				signatureMime,
				signatureFileName,
			)
		}); err != nil {
			writeError(w, http.StatusInternalServerError, "unable to store signature copy")
			return
		}
		if !savedAny {
			writeError(w, http.StatusBadRequest, "enter paperwork fields before submitting")
			return
		}
		if err := withSQLiteRetry(func() error {
			return s.store.upsertLocationEmployee(r.Context(), locationNumber, *employeePatch)
		}); err != nil {
			writeError(w, http.StatusInternalServerError, "unable to save employee details")
			return
		}
		allSubmitted, err := s.store.hasEmployeePaperworkSubmission(r.Context(), locationNumber, timePunchName)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "unable to validate paperwork status")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"message":        "paperwork submitted",
			"allSubmitted":   allSubmitted,
			"locationNumber": locationNumber,
			"timePunchName":  timePunchName,
		})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func packetPlacementForType(documentType string) signaturePlacement {
	switch strings.ToLower(strings.TrimSpace(documentType)) {
	case "i9":
		return i9EmployeeSignaturePlacement
	case "w4":
		return w4EmployeeSignaturePlacement
	default:
		return signaturePlacement{
			Page:             1,
			PageHeightPoints: 792,
			TopLeftX:         100,
			TopLeftY:         680,
			BottomRightX:     430,
			BottomRightY:     705,
		}
	}
}

func packetDocumentView(doc packetDocument, packetID int64) map[string]any {
	return map[string]any{
		"id":           doc.ID,
		"packetId":     packetID,
		"documentType": doc.DocumentType,
		"status":       doc.Status,
		"signedCount":  doc.SignedCount,
		"required":     doc.RequiredSignatures,
		"signature": map[string]any{
			"page":     doc.SignaturePage,
			"topLeftX": doc.SignatureTopLeftX,
			"topLeftY": doc.SignatureTopLeftY,
			"width":    doc.SignatureWidth,
			"height":   doc.SignatureHeight,
			"zoom":     doc.SignatureZoom,
		},
	}
}

func packetSummaryView(packet employeeDocumentPacket, docs []packetDocument) map[string]any {
	total := len(docs)
	signed := 0
	next := ""
	documentViews := make([]map[string]any, 0, len(docs))
	for _, doc := range docs {
		if doc.SignedCount >= doc.RequiredSignatures && doc.RequiredSignatures > 0 {
			signed += 1
		} else if next == "" {
			next = doc.DocumentType
		}
		documentViews = append(documentViews, packetDocumentView(doc, packet.ID))
	}
	return map[string]any{
		"packet": map[string]any{
			"id":             packet.ID,
			"status":         packet.Status,
			"locationNumber": packet.LocationNumber,
			"timePunchName":  packet.TimePunchName,
			"signedCount":    signed,
			"requiredCount":  total,
			"nextDocument":   next,
		},
		"documents": documentViews,
	}
}

func parsePacketID(raw string) (int64, bool) {
	id, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil || id <= 0 {
		return 0, false
	}
	return id, true
}

func (s *server) publicEmployeePaperworkPacketRoutes(w http.ResponseWriter, r *http.Request, locationNumber, timePunchName string, routeParts []string) {
	if len(routeParts) == 0 || !strings.EqualFold(strings.TrimSpace(routeParts[0]), "packets") {
		http.NotFound(w, r)
		return
	}
	switch {
	case len(routeParts) == 1:
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		packet, err := s.store.getOrCreateActiveEmployeePacket(r.Context(), locationNumber, timePunchName)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "unable to load packet")
			return
		}
		docs, err := s.store.listPacketDocuments(r.Context(), packet.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "unable to load packet documents")
			return
		}
		writeJSON(w, http.StatusOK, packetSummaryView(packet, docs))
		return
	case len(routeParts) == 2 && strings.EqualFold(strings.TrimSpace(routeParts[1]), "validate"):
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.publicEmployeePaperworkValidatePacket(w, r, locationNumber, timePunchName, 0)
		return
	case len(routeParts) == 3:
		packetID, ok := parsePacketID(routeParts[1])
		if !ok {
			writeError(w, http.StatusBadRequest, "invalid packet id")
			return
		}
		action := strings.ToLower(strings.TrimSpace(routeParts[2]))
		switch action {
		case "validate":
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			s.publicEmployeePaperworkValidatePacket(w, r, locationNumber, timePunchName, packetID)
			return
		case "signatures":
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			s.publicEmployeePaperworkSignPacketDocument(w, r, locationNumber, timePunchName, packetID)
			return
		case "finalize":
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			s.publicEmployeePaperworkFinalizePacket(w, r, locationNumber, timePunchName, packetID)
			return
		default:
			http.NotFound(w, r)
			return
		}
	case len(routeParts) == 5 && strings.EqualFold(strings.TrimSpace(routeParts[2]), "documents") && strings.EqualFold(strings.TrimSpace(routeParts[4]), "file"):
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		packetID, ok := parsePacketID(routeParts[1])
		if !ok {
			writeError(w, http.StatusBadRequest, "invalid packet id")
			return
		}
		documentType := strings.ToLower(strings.TrimSpace(routeParts[3]))
		s.publicEmployeePaperworkPacketDocumentFile(w, r, locationNumber, timePunchName, packetID, documentType)
		return
	default:
		http.NotFound(w, r)
		return
	}
}

func (s *server) publicEmployeePaperworkValidatePacket(w http.ResponseWriter, r *http.Request, locationNumber, timePunchName string, packetID int64) {
	contentType := strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Type")))
	isMultipart := strings.HasPrefix(contentType, "multipart/form-data")
	if isMultipart {
		if err := r.ParseMultipartForm(36 << 20); err != nil {
			writeError(w, http.StatusBadRequest, "invalid paperwork form")
			return
		}
	} else {
		if err := r.ParseForm(); err != nil {
			writeError(w, http.StatusBadRequest, "invalid paperwork form")
			return
		}
	}
	emp, err := s.store.getLocationEmployee(r.Context(), locationNumber, timePunchName)
	if err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "employee not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load employee")
		return
	}
	s.applyPaperworkDefaults(r.Context(), locationNumber, r.PostForm)
	employeePatch, err := paperworkEmployeePatchFromForm(emp, r.PostForm)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	target := strings.ToLower(strings.TrimSpace(r.PostForm.Get("paperwork_target")))
	saveI9 := target == "" || target == "i9" || target == "both" || target == "all"
	saveW4 := target == "w4" || target == "both" || target == "all"
	if !saveI9 && !saveW4 {
		writeError(w, http.StatusBadRequest, "invalid paperwork target")
		return
	}
	if normalizedState := normalizeUSStateCode(r.PostForm.Get("state")); normalizedState != "" {
		r.PostForm.Set("state", normalizedState)
	}
	var i9Data []byte
	var w4Data []byte
	var i9Uploads []i9SupportingDocumentUpload
	if saveI9 {
		if !isMultipart {
			writeError(w, http.StatusBadRequest, "upload at least one i-9 supporting document")
			return
		}
		i9Uploads, err = collectI9SupportingDocumentsFromRequest(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := validateI9DocumentRequirements(i9Uploads); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		applyI9DocumentValuesToForm(r.PostForm, i9Uploads)
		i9Data, err = generateFilledI9PDF(r.PostForm)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	if saveW4 {
		if err := normalizeW4DollarFields(r.PostForm); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		w4Data, err = generateFilledW4PDF(r.PostForm)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	if err := withSQLiteRetry(func() error {
		return s.store.upsertLocationEmployee(r.Context(), locationNumber, *employeePatch)
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "unable to save employee details")
		return
	}
	var packet employeeDocumentPacket
	if packetID > 0 {
		packet, err = s.store.getPacketByIDForEmployee(r.Context(), packetID, locationNumber, timePunchName)
		if err != nil {
			if errors.Is(err, errNotFound) {
				writeError(w, http.StatusNotFound, "packet not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "unable to load packet")
			return
		}
	} else {
		packet, err = s.store.getOrCreateActiveEmployeePacket(r.Context(), locationNumber, timePunchName)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "unable to prepare packet")
			return
		}
	}
	if saveI9 {
		i9Template, err := s.store.getDocumentTemplateByType(r.Context(), "i9")
		if err != nil {
			writeError(w, http.StatusInternalServerError, "unable to load i9 template metadata")
			return
		}
		if err := withSQLiteRetry(func() error {
			return s.store.upsertPacketDocument(r.Context(), packet.ID, "i9", i9Template, i9Data, "application/pdf", "i9-filled.pdf")
		}); err != nil {
			writeError(w, http.StatusInternalServerError, "unable to prepare i9 packet document")
			return
		}
		if err := withSQLiteRetry(func() error {
			return s.store.deleteEmployeeI9DocumentsForEmployee(r.Context(), locationNumber, timePunchName)
		}); err != nil {
			writeError(w, http.StatusInternalServerError, "unable to reset i9 documents")
			return
		}
		for _, upload := range i9Uploads {
			current := upload
			if err := withSQLiteRetry(func() error {
				return s.store.addEmployeeI9Document(
					r.Context(),
					locationNumber,
					timePunchName,
					current.ListType,
					current.DocumentTitle,
					current.IssuingAuthority,
					current.DocumentNumber,
					current.ExpirationDate,
					current.Data,
					current.Mime,
					current.FileName,
				)
			}); err != nil {
				writeError(w, http.StatusInternalServerError, "unable to persist i9 supporting document")
				return
			}
		}
	}
	if saveW4 {
		w4Template, err := s.store.getDocumentTemplateByType(r.Context(), "w4")
		if err != nil {
			writeError(w, http.StatusInternalServerError, "unable to load w4 template metadata")
			return
		}
		if err := withSQLiteRetry(func() error {
			return s.store.upsertPacketDocument(r.Context(), packet.ID, "w4", w4Template, w4Data, "application/pdf", "w4-filled.pdf")
		}); err != nil {
			writeError(w, http.StatusInternalServerError, "unable to prepare w4 packet document")
			return
		}
	}
	if err := withSQLiteRetry(func() error {
		return s.store.updatePacketStatus(r.Context(), packet.ID, "ready_to_sign", false)
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "unable to update packet status")
		return
	}
	packet, err = s.store.getPacketByIDForEmployee(r.Context(), packet.ID, locationNumber, timePunchName)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to reload packet")
		return
	}
	docs, err := s.store.listPacketDocuments(r.Context(), packet.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to load packet documents")
		return
	}
	writeJSON(w, http.StatusOK, packetSummaryView(packet, docs))
}

func (s *server) publicEmployeePaperworkSignPacketDocument(w http.ResponseWriter, r *http.Request, locationNumber, timePunchName string, packetID int64) {
	packet, err := s.store.getPacketByIDForEmployee(r.Context(), packetID, locationNumber, timePunchName)
	if err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "packet not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load packet")
		return
	}
	if packet.Status == "finalized" {
		writeError(w, http.StatusConflict, "packet has already been finalized")
		return
	}
	var req packetSignatureRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid signature payload")
		return
	}
	documentType := strings.ToLower(strings.TrimSpace(req.DocumentType))
	if documentType == "" {
		writeError(w, http.StatusBadRequest, "documentType is required")
		return
	}
	signatureData := strings.TrimSpace(req.SignatureDataURL)
	if signatureData == "" {
		writeError(w, http.StatusBadRequest, "signatureDataUrl is required")
		return
	}
	signatureImageData, _, err := parseDataURLBinary(signatureData, []string{"image/png", "image/jpeg", "image/webp"}, 2<<20)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid signatureDataUrl")
		return
	}
	doc, err := s.store.getPacketDocumentByType(r.Context(), packetID, documentType)
	if err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "document not found in packet")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load packet document")
		return
	}
	placement := packetPlacementForType(documentType)
	placement.Page = doc.SignaturePage
	placement.TopLeftX = doc.SignatureTopLeftX
	placement.TopLeftY = doc.SignatureTopLeftY
	placement.BottomRightX = doc.SignatureTopLeftX + doc.SignatureWidth
	placement.BottomRightY = doc.SignatureTopLeftY + doc.SignatureHeight
	if strings.TrimSpace(doc.FormFieldName) != "" {
		placement.FormFieldName = strings.TrimSpace(doc.FormFieldName)
	}
	signedPDF, err := stampDrawnSignatureOnPDF(doc.FileData, signatureImageData, placement)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	signedFileName := strings.TrimSpace(doc.FileName)
	if signedFileName == "" {
		signedFileName = strings.ToLower(documentType) + "-signed.pdf"
	}
	if err := withSQLiteRetry(func() error {
		return s.store.markPacketDocumentSigned(r.Context(), doc.ID, signedPDF, "application/pdf", signedFileName)
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "unable to persist signed document")
		return
	}
	signatureHash := sha256.Sum256(signatureImageData)
	remoteIP := strings.TrimSpace(r.RemoteAddr)
	if host, _, splitErr := net.SplitHostPort(r.RemoteAddr); splitErr == nil && strings.TrimSpace(host) != "" {
		remoteIP = host
	}
	signerName := strings.TrimSpace(req.SignerDisplayName)
	if signerName == "" {
		signerName = timePunchName
	}
	if err := withSQLiteRetry(func() error {
		return s.store.addSignatureEvent(
			r.Context(),
			packetID,
			doc.ID,
			locationNumber,
			timePunchName,
			signerName,
			remoteIP,
			r.UserAgent(),
			"sign_document",
			hex.EncodeToString(signatureHash[:]),
			1,
		)
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "unable to persist signature event")
		return
	}
	if err := withSQLiteRetry(func() error {
		return s.store.updatePacketStatus(r.Context(), packetID, "signing", false)
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "unable to update packet status")
		return
	}
	packet, err = s.store.getPacketByIDForEmployee(r.Context(), packetID, locationNumber, timePunchName)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to reload packet")
		return
	}
	docs, err := s.store.listPacketDocuments(r.Context(), packetID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to load packet documents")
		return
	}
	writeJSON(w, http.StatusOK, packetSummaryView(packet, docs))
}

func (s *server) publicEmployeePaperworkFinalizePacket(w http.ResponseWriter, r *http.Request, locationNumber, timePunchName string, packetID int64) {
	packet, err := s.store.getPacketByIDForEmployee(r.Context(), packetID, locationNumber, timePunchName)
	if err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "packet not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load packet")
		return
	}
	if packet.Status == "finalized" {
		writeJSON(w, http.StatusOK, map[string]any{
			"message":      "packet finalized",
			"allSubmitted": true,
		})
		return
	}
	docs, err := s.store.listPacketDocuments(r.Context(), packetID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to load packet documents")
		return
	}
	if len(docs) == 0 {
		writeError(w, http.StatusBadRequest, "packet has no documents to finalize")
		return
	}
	for _, doc := range docs {
		if doc.RequiredSignatures <= 0 {
			continue
		}
		if doc.SignedCount < doc.RequiredSignatures || len(doc.SignedFileData) == 0 {
			writeError(w, http.StatusBadRequest, "all required signatures must be completed before finalize")
			return
		}
	}
	for _, doc := range docs {
		docType := strings.ToLower(strings.TrimSpace(doc.DocumentType))
		switch docType {
		case "i9":
			if err := withSQLiteRetry(func() error {
				return s.store.upsertEmployeeI9Form(r.Context(), locationNumber, timePunchName, doc.SignedFileData, "application/pdf", "i9-filled.pdf")
			}); err != nil {
				writeError(w, http.StatusInternalServerError, "unable to persist i9 form")
				return
			}
		case "w4":
			if err := withSQLiteRetry(func() error {
				return s.store.upsertEmployeeW4Form(r.Context(), locationNumber, timePunchName, doc.SignedFileData, "application/pdf", "w4-filled.pdf")
			}); err != nil {
				writeError(w, http.StatusInternalServerError, "unable to persist w4 form")
				return
			}
		}
	}
	if err := withSQLiteRetry(func() error {
		return s.store.updatePacketStatus(r.Context(), packetID, "finalized", true)
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "unable to finalize packet")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"message":        "paperwork submitted",
		"allSubmitted":   true,
		"locationNumber": locationNumber,
		"timePunchName":  timePunchName,
	})
}

func (s *server) publicEmployeePaperworkPacketDocumentFile(w http.ResponseWriter, r *http.Request, locationNumber, timePunchName string, packetID int64, documentType string) {
	_, err := s.store.getPacketByIDForEmployee(r.Context(), packetID, locationNumber, timePunchName)
	if err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "packet not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load packet")
		return
	}
	doc, err := s.store.getPacketDocumentByType(r.Context(), packetID, documentType)
	if err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "document not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load packet document")
		return
	}
	data := doc.FileData
	name := doc.FileName
	if len(doc.SignedFileData) > 0 {
		data = doc.SignedFileData
	}
	if strings.TrimSpace(name) == "" {
		name = strings.ToLower(strings.TrimSpace(documentType)) + ".pdf"
	}
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", "inline; filename=\""+name+"\"")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (s *server) publicCandidateInterviewHandler(w http.ResponseWriter, r *http.Request) {
	trimmed := strings.TrimPrefix(r.URL.Path, "/api/public/interview/")
	trimmed = strings.Trim(trimmed, "/")
	if trimmed == "" {
		http.NotFound(w, r)
		return
	}
	token := strings.TrimSpace(trimmed)
	record, err := s.store.getCandidateInterviewToken(r.Context(), token)
	if err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "invalid or closed interview link")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to validate interview link")
		return
	}
	candidateRecord, err := s.store.getCandidateByID(r.Context(), record.LocationNumber, record.CandidateID)
	if err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "candidate not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load candidate")
		return
	}
	if candidateRecord.Status != "active" {
		writeError(w, http.StatusGone, "candidate is no longer available for interview")
		return
	}
	values, err := s.store.listCandidateValues(r.Context(), record.LocationNumber)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to load candidate values")
		return
	}
	interviewName, err := s.resolveInterviewNameForLocation(r.Context(), record.LocationNumber, record.InterviewType)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to load interview types")
		return
	}
	if interviewName == "" {
		writeError(w, http.StatusBadRequest, "this interview link references an invalid interview type")
		return
	}
	interviewNameID, err := s.resolveInterviewNameIDForLocation(r.Context(), record.LocationNumber, interviewName)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to load interview types")
		return
	}
	questions, err := s.store.listCandidateInterviewQuestions(r.Context(), record.LocationNumber, interviewNameID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to load interview questions")
		return
	}
	if len(questions) == 0 {
		writeError(w, http.StatusBadRequest, "create at least one interview question for this interview type before interviewing")
		return
	}
	switch r.Method {
	case http.MethodGet:
		loc, err := s.store.getLocationByNumber(r.Context(), record.LocationNumber)
		if err != nil {
			if errors.Is(err, errNotFound) {
				writeError(w, http.StatusNotFound, "location not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "unable to load location")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"locationNumber":           record.LocationNumber,
			"locationName":             loc.Name,
			"candidateId":              candidateRecord.ID,
			"candidateFirstName":       candidateRecord.FirstName,
			"candidateLastName":        candidateRecord.LastName,
			"interviewerTimePunchName": record.InterviewerTimePunchName,
			"interviewType":            record.InterviewType,
			"values":                   values,
			"questions":                questions,
		})
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			writeError(w, http.StatusBadRequest, "invalid interview form")
			return
		}
		interviewGrades := make([]candidateInterviewGrade, 0, len(values))
		for _, value := range values {
			grade := normalizeLetterGrade(r.PostForm.Get("grade_" + strconv.FormatInt(value.ID, 10)))
			if grade == "" {
				writeError(w, http.StatusBadRequest, "every value must be graded with A, B, C, D, or F")
				return
			}
			comment := strings.TrimSpace(r.PostForm.Get("comment_" + strconv.FormatInt(value.ID, 10)))
			if comment == "" {
				writeError(w, http.StatusBadRequest, "every value must include a comment")
				return
			}
			if len([]rune(comment)) > 1000 {
				writeError(w, http.StatusBadRequest, "value comments must be 1000 characters or fewer")
				return
			}
			interviewGrades = append(interviewGrades, candidateInterviewGrade{
				ValueID:     value.ID,
				ValueName:   value.Name,
				LetterGrade: grade,
				Comment:     comment,
				Score:       letterGradeScore(grade),
			})
		}
		questionAnswers := make([]candidateInterviewQuestionAnswer, 0, len(questions))
		for _, question := range questions {
			answer := strings.TrimSpace(r.PostForm.Get("question_" + strconv.FormatInt(question.ID, 10)))
			if err := validateCandidateInterviewQuestionAnswer(question, answer); err != nil {
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}
			questionAnswers = append(questionAnswers, candidateInterviewQuestionAnswer{
				QuestionID:   question.ID,
				QuestionText: question.Question,
				Answer:       answer,
			})
		}
		notes := strings.TrimSpace(r.PostForm.Get("notes"))
		if len([]rune(notes)) > 3000 {
			writeError(w, http.StatusBadRequest, "notes must be 3000 characters or fewer")
			return
		}
		interview := candidateInterview{
			CandidateID:              record.CandidateID,
			LocationNumber:           record.LocationNumber,
			InterviewerTimePunchName: record.InterviewerTimePunchName,
			InterviewType:            record.InterviewType,
			Notes:                    notes,
			CreatedAt:                time.Now().UTC(),
			Grades:                   interviewGrades,
			QuestionAnswers:          questionAnswers,
		}
		id, err := s.store.createCandidateInterview(r.Context(), interview)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "unable to create interview")
			return
		}
		_ = s.store.markCandidateInterviewTokenUsed(r.Context(), token)
		interview.ID = id
		writeJSON(w, http.StatusOK, map[string]any{
			"message":   "interview submitted",
			"candidate": candidateRecord,
			"interview": interview,
		})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func applyI9SignatureNameFallback(values url.Values) {
	if values == nil {
		return
	}
	drawn := strings.TrimSpace(values.Get("employee_signature_drawn"))
	typed := strings.TrimSpace(values.Get("employee_signature"))
	if drawn == "" || typed != "" {
		return
	}
	first := strings.TrimSpace(values.Get("first_name"))
	last := strings.TrimSpace(values.Get("last_name"))
	fallback := strings.TrimSpace(first + " " + last)
	if fallback == "" {
		return
	}
	values.Set("employee_signature", fallback)
}

type i9SupportingDocumentUpload struct {
	ListType         string
	DocumentTitle    string
	IssuingAuthority string
	DocumentNumber   string
	ExpirationDate   string
	Data             []byte
	Mime             string
	FileName         string
}

type signaturePlacement struct {
	Page             int
	PageHeightPoints float64
	TopLeftX         float64
	TopLeftY         float64
	BottomRightX     float64
	BottomRightY     float64
	// FormFieldName is the PDF form-field annotation that covers the signature
	// box. When set, stampDrawnSignatureOnPDF removes it before stamping so the
	// empty annotation cannot paint over the image stamp in the content stream.
	FormFieldName string
}

var (
	// w4EmployeeSignaturePlacement positions the drawn signature on the W-4.
	// This is a fallback default and is overridden at startup when
	// docs/chords.TXT or docs/cords.txt is present.
	// Fallback coordinates are derived from the "signature" widget annotation in docs/w4.pdf:
	//   Rect = [99.0, 92.0, 440.0, 114.0]  (PDF points, y from bottom of page)
	// Converted to our top-of-page origin system (pageHeight - pdfY):
	//   TopLeftY    = 791.97 - 114.0 = 677.97  (top edge of the field)
	//   BottomRightY = 791.97 - 92.0  = 699.97  (bottom edge of the field)
	w4EmployeeSignaturePlacement = signaturePlacement{
		Page:             1,
		PageHeightPoints: 791.97,
		TopLeftX:         99.00,
		TopLeftY:         677.97,
		BottomRightX:     440.00,
		BottomRightY:     699.97,
		FormFieldName:    "signature",
	}
	// i9EmployeeSignaturePlacement positions the drawn signature on the I-9.
	// This is a fallback default and is overridden at startup when
	// docs/chords.TXT or docs/cords.txt is present.
	// Fallback coordinates are derived from the "signature_box" widget annotation in docs/i9.pdf:
	//   Rect = [118.0, 422.0, 366.0, 442.0]  (PDF points, y from bottom of page)
	// Converted to our top-of-page origin system (pageHeight - pdfY):
	//   TopLeftY    = 792 - 442 = 350.0
	//   BottomRightY = 792 - 422 = 370.0
	i9EmployeeSignaturePlacement = signaturePlacement{
		Page:             1,
		PageHeightPoints: 792,
		TopLeftX:         118.00,
		TopLeftY:         350.00,
		BottomRightX:     366.00,
		BottomRightY:     370.00,
		FormFieldName:    "signature_box",
	}
)

func init() {
	overrideSignaturePlacementsFromDocs()
}

func overrideSignaturePlacementsFromDocs() {
	coordsPath := resolveSignatureCoordsPath()
	if coordsPath == "" {
		return
	}
	placements, err := parseSignaturePlacementsFromCoordsFile(coordsPath)
	if err != nil {
		log.Printf("warning: unable to parse signature coordinates from %s: %v", coordsPath, err)
		return
	}
	if p, ok := placements["w4"]; ok {
		resolved := resolvePlacementForPageCoords(p, w4EmployeeSignaturePlacement)
		if placementIsReasonableOverride(resolved, w4EmployeeSignaturePlacement) {
			w4EmployeeSignaturePlacement.TopLeftX = resolved.TopLeftX
			w4EmployeeSignaturePlacement.TopLeftY = resolved.TopLeftY
			w4EmployeeSignaturePlacement.BottomRightX = resolved.BottomRightX
			w4EmployeeSignaturePlacement.BottomRightY = resolved.BottomRightY
		} else {
			log.Printf("warning: ignoring W4 signature coordinates from %s because they are too far from the template signature field", coordsPath)
		}
	}
	if p, ok := placements["i9"]; ok {
		resolved := resolvePlacementForPageCoords(p, i9EmployeeSignaturePlacement)
		if placementIsReasonableOverride(resolved, i9EmployeeSignaturePlacement) {
			i9EmployeeSignaturePlacement.TopLeftX = resolved.TopLeftX
			i9EmployeeSignaturePlacement.TopLeftY = resolved.TopLeftY
			i9EmployeeSignaturePlacement.BottomRightX = resolved.BottomRightX
			i9EmployeeSignaturePlacement.BottomRightY = resolved.BottomRightY
		} else {
			log.Printf("warning: ignoring I9 signature coordinates from %s because they are too far from the template signature field", coordsPath)
		}
	}
}

// resolvePlacementForPageCoords chooses between:
// - top-origin coordinates (what this server uses), and
// - bottom-origin PDF coordinates (common from PDF annotation tools),
// by selecting the candidate nearest the known template field.
func resolvePlacementForPageCoords(candidate, fallback signaturePlacement) signaturePlacement {
	topOrigin := candidate
	bottomOrigin := candidate
	bottomOrigin.TopLeftY = fallback.PageHeightPoints - candidate.BottomRightY
	bottomOrigin.BottomRightY = fallback.PageHeightPoints - candidate.TopLeftY
	if placementDistance(bottomOrigin, fallback) < placementDistance(topOrigin, fallback) {
		return bottomOrigin
	}
	return topOrigin
}

func placementDistance(a, b signaturePlacement) float64 {
	return math.Abs(a.TopLeftX-b.TopLeftX) +
		math.Abs(a.TopLeftY-b.TopLeftY) +
		math.Abs(a.BottomRightX-b.BottomRightX) +
		math.Abs(a.BottomRightY-b.BottomRightY)
}

func placementIsReasonableOverride(candidate, fallback signaturePlacement) bool {
	if candidate.BottomRightX <= candidate.TopLeftX || candidate.BottomRightY <= candidate.TopLeftY {
		return false
	}
	// Keep user-provided tuning, but avoid obviously wrong coordinates.
	// If the box differs by too much from the template field, prefer fallback.
	return placementDistance(candidate, fallback) <= 180
}

func resolveSignatureCoordsPath() string {
	candidates := []string{
		filepath.Join("docs", "chords.TXT"),
		filepath.Join("docs", "chords.txt"),
		filepath.Join("docs", "cords.TXT"),
		filepath.Join("docs", "cords.txt"),
	}
	for _, candidate := range candidates {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate
		}
	}
	return ""
}

func parseSignaturePlacementsFromCoordsFile(path string) (map[string]signaturePlacement, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	linePattern := regexp.MustCompile(`(?i)^\s*(w4|i9)\s*:\s*(.+?)\s*$`)
	pointPattern := regexp.MustCompile(`\(\s*(-?\d+(?:\.\d+)?)\s*,\s*(-?\d+(?:\.\d+)?)\s*\)`)
	placements := make(map[string]signaturePlacement)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		match := linePattern.FindStringSubmatch(line)
		if len(match) != 3 {
			continue
		}
		docType := strings.ToLower(strings.TrimSpace(match[1]))
		points := pointPattern.FindAllStringSubmatch(match[2], -1)
		// Accept the normal format: top-left and bottom-right points.
		// Also tolerate extra points and compute a bounding box from all points.
		if len(points) < 2 {
			return nil, fmt.Errorf("%s line must include at least 2 (x,y) points: %q", strings.ToUpper(docType), line)
		}
		minX := math.MaxFloat64
		minY := math.MaxFloat64
		maxX := -math.MaxFloat64
		maxY := -math.MaxFloat64
		for _, point := range points {
			x, xErr := strconv.ParseFloat(strings.TrimSpace(point[1]), 64)
			if xErr != nil {
				return nil, fmt.Errorf("%s has invalid X coordinate %q", strings.ToUpper(docType), point[1])
			}
			y, yErr := strconv.ParseFloat(strings.TrimSpace(point[2]), 64)
			if yErr != nil {
				return nil, fmt.Errorf("%s has invalid Y coordinate %q", strings.ToUpper(docType), point[2])
			}
			if x < minX {
				minX = x
			}
			if x > maxX {
				maxX = x
			}
			if y < minY {
				minY = y
			}
			if y > maxY {
				maxY = y
			}
		}
		placements[docType] = signaturePlacement{
			TopLeftX:     minX,
			TopLeftY:     minY,
			BottomRightX: maxX,
			BottomRightY: maxY,
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return placements, nil
}

func collectI9SupportingDocumentsFromRequest(r *http.Request) ([]i9SupportingDocumentUpload, error) {
	if r == nil || r.MultipartForm == nil {
		return nil, errors.New("upload at least one i-9 supporting document")
	}
	listValues := r.MultipartForm.Value["i9_document_list[]"]
	if len(listValues) == 0 {
		listValues = r.MultipartForm.Value["i9_document_list"]
	}
	titleValues := r.MultipartForm.Value["i9_document_title[]"]
	if len(titleValues) == 0 {
		titleValues = r.MultipartForm.Value["i9_document_title"]
	}
	authorityValues := r.MultipartForm.Value["i9_document_issuing_authority[]"]
	if len(authorityValues) == 0 {
		authorityValues = r.MultipartForm.Value["i9_document_issuing_authority"]
	}
	numberValues := r.MultipartForm.Value["i9_document_number[]"]
	if len(numberValues) == 0 {
		numberValues = r.MultipartForm.Value["i9_document_number"]
	}
	expirationValues := r.MultipartForm.Value["i9_document_expiration[]"]
	if len(expirationValues) == 0 {
		expirationValues = r.MultipartForm.Value["i9_document_expiration"]
	}
	fileHeaders := r.MultipartForm.File["i9_document_file[]"]
	if len(fileHeaders) == 0 {
		fileHeaders = r.MultipartForm.File["i9_document_file"]
	}
	if len(fileHeaders) == 0 {
		return nil, errors.New("upload at least one i-9 supporting document")
	}

	uploads := make([]i9SupportingDocumentUpload, 0, len(fileHeaders))
	for idx, header := range fileHeaders {
		if header == nil {
			continue
		}
		if idx >= len(listValues) {
			return nil, errors.New("choose list A, B, or C for each uploaded i-9 document")
		}
		if idx >= len(titleValues) || idx >= len(authorityValues) || idx >= len(numberValues) {
			return nil, errors.New("enter document title, issuing authority, and document number for each uploaded i-9 document")
		}
		listType, ok := normalizeI9ListType(listValues[idx])
		if !ok {
			return nil, errors.New("choose list A, B, or C for each uploaded i-9 document")
		}
		documentTitle := strings.TrimSpace(titleValues[idx])
		issuingAuthority := strings.TrimSpace(authorityValues[idx])
		documentNumber := strings.TrimSpace(numberValues[idx])
		if documentTitle == "" || issuingAuthority == "" || documentNumber == "" {
			return nil, errors.New("enter document title, issuing authority, and document number for each uploaded i-9 document")
		}
		expiration := ""
		if idx < len(expirationValues) {
			expiration = strings.TrimSpace(expirationValues[idx])
		}
		raw, mime, fileName, err := readMultipartFileHeader(header, 12<<20, []string{"application/pdf", "image/png", "image/jpeg", "image/webp"})
		if err != nil {
			return nil, err
		}
		pdfData, pdfName, err := convertDocumentToPDF(raw, mime, fileName)
		if err != nil {
			return nil, err
		}
		uploads = append(uploads, i9SupportingDocumentUpload{
			ListType:         listType,
			DocumentTitle:    documentTitle,
			IssuingAuthority: issuingAuthority,
			DocumentNumber:   documentNumber,
			ExpirationDate:   expiration,
			Data:             pdfData,
			Mime:             "application/pdf",
			FileName:         pdfName,
		})
	}
	if len(uploads) == 0 {
		return nil, errors.New("upload at least one i-9 supporting document")
	}
	return uploads, nil
}

func normalizeI9ListType(value string) (string, bool) {
	normalized := strings.ToLower(strings.TrimSpace(value))
	switch normalized {
	case "a", "list a", "list_a", "list-a":
		return "a", true
	case "b", "list b", "list_b", "list-b":
		return "b", true
	case "c", "list c", "list_c", "list-c":
		return "c", true
	}
	return "", false
}

func validateI9DocumentRequirements(uploads []i9SupportingDocumentUpload) error {
	if len(uploads) == 0 {
		return errors.New("upload at least one i-9 supporting document")
	}
	hasA := false
	hasB := false
	hasC := false
	for _, upload := range uploads {
		switch strings.TrimSpace(strings.ToLower(upload.ListType)) {
		case "a":
			hasA = true
		case "b":
			hasB = true
		case "c":
			hasC = true
		}
	}
	if hasA || (hasB && hasC) {
		return nil
	}
	return errors.New("i-9 documents must include either one List A document, or one List B and one List C document")
}

func applyI9DocumentValuesToForm(values url.Values, uploads []i9SupportingDocumentUpload) {
	if values == nil || len(uploads) == 0 {
		return
	}
	// Clear all list fields first so regenerated submissions do not keep stale values.
	for _, key := range []string{
		"list_a_title", "list_a_issuing_authority", "list_a_number", "list_a_expiration",
		"list_b_title", "list_b_issuing_authority", "list_b_number", "list_b_expiration",
		"list_c_title", "list_c_issuing_authority", "list_c_number", "list_c_expiration",
	} {
		values.Del(key)
	}
	setIfEmpty := func(key, val string) {
		if strings.TrimSpace(values.Get(key)) != "" {
			return
		}
		val = strings.TrimSpace(val)
		if val == "" {
			return
		}
		values.Set(key, val)
	}
	for _, upload := range uploads {
		switch strings.TrimSpace(strings.ToLower(upload.ListType)) {
		case "a":
			setIfEmpty("list_a_title", upload.DocumentTitle)
			setIfEmpty("list_a_issuing_authority", upload.IssuingAuthority)
			setIfEmpty("list_a_number", upload.DocumentNumber)
			setIfEmpty("list_a_expiration", upload.ExpirationDate)
		case "b":
			setIfEmpty("list_b_title", upload.DocumentTitle)
			setIfEmpty("list_b_issuing_authority", upload.IssuingAuthority)
			setIfEmpty("list_b_number", upload.DocumentNumber)
			setIfEmpty("list_b_expiration", upload.ExpirationDate)
		case "c":
			setIfEmpty("list_c_title", upload.DocumentTitle)
			setIfEmpty("list_c_issuing_authority", upload.IssuingAuthority)
			setIfEmpty("list_c_number", upload.DocumentNumber)
			setIfEmpty("list_c_expiration", upload.ExpirationDate)
		}
	}
}

func readMultipartFileHeader(header *multipart.FileHeader, maxBytes int64, allowedMimes []string) ([]byte, string, string, error) {
	if header == nil {
		return nil, "", "", errors.New("uploaded file is missing")
	}
	file, err := header.Open()
	if err != nil {
		return nil, "", "", errors.New("unable to open uploaded file")
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maxBytes))
	if err != nil {
		return nil, "", "", errors.New("unable to read uploaded file")
	}
	if len(raw) == 0 {
		return nil, "", "", errors.New("uploaded file is empty")
	}
	mime := http.DetectContentType(raw)
	allowed := false
	for _, candidate := range allowedMimes {
		if strings.EqualFold(strings.TrimSpace(candidate), mime) {
			allowed = true
			break
		}
	}
	if !allowed {
		return nil, "", "", errors.New("i-9 supporting documents must be a PDF or image file")
	}
	return raw, mime, strings.TrimSpace(header.Filename), nil
}

func convertDocumentToPDF(data []byte, mime, fileName string) ([]byte, string, error) {
	if len(data) == 0 {
		return nil, "", errors.New("uploaded file is empty")
	}
	mime = strings.TrimSpace(strings.ToLower(mime))
	if mime == "application/pdf" {
		return data, ensurePDFFileName(fileName), nil
	}
	switch mime {
	case "image/png", "image/jpeg", "image/webp":
	default:
		return nil, "", errors.New("i-9 supporting documents must be a PDF or image file")
	}
	pdfcpuPath, err := resolvePdfcpuPath()
	if err != nil {
		return nil, "", errors.New("pdfcpu is required on the host to convert i-9 supporting documents")
	}
	tmpDir, err := os.MkdirTemp("", "cfasuite-i9-doc-*")
	if err != nil {
		return nil, "", errors.New("unable to prepare i-9 document conversion")
	}
	defer func() {
		_ = os.RemoveAll(tmpDir)
	}()
	decodedImg, _, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		if webpDecoded, decodeErr := webp.Decode(bytes.NewReader(data)); decodeErr == nil {
			decodedImg = webpDecoded
		} else {
			return nil, "", errors.New("unable to decode uploaded image")
		}
	}
	inputPath := filepath.Join(tmpDir, "input.png")
	outputPath := filepath.Join(tmpDir, "output.pdf")
	inputFile, err := os.Create(inputPath)
	if err != nil {
		return nil, "", errors.New("unable to stage i-9 document conversion")
	}
	if err := png.Encode(inputFile, decodedImg); err != nil {
		_ = inputFile.Close()
		return nil, "", errors.New("unable to stage i-9 document conversion")
	}
	if err := inputFile.Close(); err != nil {
		return nil, "", errors.New("unable to stage i-9 document conversion")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	if output, err := exec.CommandContext(ctx, pdfcpuPath, "import", outputPath, inputPath).CombinedOutput(); err != nil {
		return nil, "", fmt.Errorf("unable to convert i-9 supporting document to pdf: %s", strings.TrimSpace(string(output)))
	}
	converted, err := os.ReadFile(outputPath)
	if err != nil {
		return nil, "", errors.New("unable to read converted i-9 pdf")
	}
	if len(converted) == 0 {
		return nil, "", errors.New("converted i-9 pdf is empty")
	}
	return converted, ensurePDFFileName(fileName), nil
}

// resolvePdfcpuPath returns the path to the pdfcpu binary. It checks:
// 1) managed local binary in ./bin, 2) PATH, then 3) auto-download into ./bin.
func resolvePdfcpuPath() (string, error) {
	localPath := localPdfcpuBinaryPath()
	if info, err := os.Stat(localPath); err == nil && info.Mode()&0o111 != 0 {
		return localPath, nil
	}
	if path, err := exec.LookPath("pdfcpu"); err == nil {
		return path, nil
	}
	ensurePdfcpuOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		ensurePdfcpuErr = ensurePdfcpuDownload(ctx, localPath)
	})
	if ensurePdfcpuErr != nil {
		return "", ensurePdfcpuErr
	}
	if info, err := os.Stat(localPath); err == nil && info.Mode()&0o111 != 0 {
		return localPath, nil
	}
	return exec.LookPath("pdfcpu")
}

func localPdfcpuBinaryPath() string {
	name := "pdfcpu"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return filepath.Join("bin", name)
}

func ensurePdfcpuDownload(ctx context.Context, destination string) error {
	if info, err := os.Stat(destination); err == nil && info.Mode()&0o111 != 0 {
		return nil
	}
	assetName, err := pdfcpuReleaseAssetName()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return fmt.Errorf("create bin directory: %w", err)
	}
	url := fmt.Sprintf("https://github.com/pdfcpu/pdfcpu/releases/download/%s/%s", pdfcpuVersion, assetName)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("prepare pdfcpu download request: %w", err)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return fmt.Errorf("download pdfcpu: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("download pdfcpu: unexpected status %s", response.Status)
	}
	if strings.HasSuffix(assetName, ".zip") {
		data, err := io.ReadAll(response.Body)
		if err != nil {
			return fmt.Errorf("read pdfcpu zip: %w", err)
		}
		return extractPdfcpuFromZip(data, destination)
	}
	return extractPdfcpuFromTarXz(response.Body, destination)
}

func pdfcpuReleaseAssetName() (string, error) {
	version := strings.TrimPrefix(pdfcpuVersion, "v")
	var osName, archName, ext string
	switch runtime.GOOS {
	case "darwin":
		osName = "Darwin"
		ext = ".tar.xz"
	case "linux":
		osName = "Linux"
		ext = ".tar.xz"
	case "windows":
		osName = "Windows"
		ext = ".zip"
	default:
		return "", fmt.Errorf("unsupported platform for automatic pdfcpu install: %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	switch runtime.GOARCH {
	case "amd64":
		archName = "x86_64"
	case "arm64":
		if runtime.GOOS == "windows" {
			archName = "x86_64"
		} else {
			archName = "arm64"
		}
	default:
		return "", fmt.Errorf("unsupported platform for automatic pdfcpu install: %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	return fmt.Sprintf("pdfcpu_%s_%s_%s%s", version, osName, archName, ext), nil
}

func extractPdfcpuFromTarXz(r io.Reader, destination string) error {
	xzr, err := xz.NewReader(r)
	if err != nil {
		return fmt.Errorf("decompress pdfcpu archive: %w", err)
	}
	tr := tar.NewReader(xzr)
	for {
		hdr, err := tr.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return fmt.Errorf("read pdfcpu archive: %w", err)
		}
		if filepath.Base(hdr.Name) == "pdfcpu" && hdr.Typeflag != tar.TypeDir {
			return writePdfcpuBinary(tr, destination)
		}
	}
	return errors.New("pdfcpu binary not found in archive")
}

func extractPdfcpuFromZip(data []byte, destination string) error {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return fmt.Errorf("open pdfcpu zip: %w", err)
	}
	for _, f := range zr.File {
		if filepath.Base(f.Name) == "pdfcpu.exe" && !f.FileInfo().IsDir() {
			rc, err := f.Open()
			if err != nil {
				return fmt.Errorf("open pdfcpu binary in zip: %w", err)
			}
			defer rc.Close()
			return writePdfcpuBinary(rc, destination)
		}
	}
	return errors.New("pdfcpu binary not found in zip")
}

func writePdfcpuBinary(r io.Reader, destination string) error {
	tmpPath := destination + ".tmp"
	file, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return fmt.Errorf("create temporary pdfcpu binary: %w", err)
	}
	if _, err := io.Copy(file, r); err != nil {
		_ = file.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("write pdfcpu binary: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close temporary pdfcpu binary: %w", err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(tmpPath, 0o755); err != nil {
			return fmt.Errorf("mark pdfcpu binary executable: %w", err)
		}
	}
	if err := os.Rename(tmpPath, destination); err != nil {
		return fmt.Errorf("install pdfcpu binary: %w", err)
	}
	return nil
}

func commandExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func ensureTool(tool string) error {
	if commandExists(tool) {
		return nil
	}
	log.Printf("note: %q not found, installing automatically", tool)
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		if !commandExists("brew") {
			return fmt.Errorf("%q is required but Homebrew is not installed", tool)
		}
		cmd = exec.Command("brew", "install", "librsvg")
	case "linux":
		switch {
		case commandExists("apt-get"):
			cmd = exec.Command("sudo", "apt-get", "install", "-y", "librsvg2-bin")
		case commandExists("dnf"):
			cmd = exec.Command("sudo", "dnf", "install", "-y", "librsvg2-tools")
		case commandExists("yum"):
			cmd = exec.Command("sudo", "yum", "install", "-y", "librsvg2-tools")
		case commandExists("pacman"):
			cmd = exec.Command("sudo", "pacman", "-S", "--noconfirm", "librsvg")
		default:
			return fmt.Errorf("%q is required; install librsvg2-bin manually", tool)
		}
	default:
		return fmt.Errorf("%q is required; install librsvg to continue", tool)
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("auto-install of %q failed: %v (%s)", tool, err, strings.TrimSpace(string(output)))
	}
	if !commandExists(tool) {
		return fmt.Errorf("%q installed but still not found in PATH", tool)
	}
	return nil
}

func ensurePaperworkDependenciesOnStartup() error {
	// Resolve/download pdfcpu at boot so first paperwork submission has no binary setup latency.
	if _, err := resolvePdfcpuPath(); err != nil {
		return fmt.Errorf("pdfcpu unavailable: %w", err)
	}
	// Resolve/install rsvg at boot so signature stamping is ready before traffic starts.
	if err := ensureTool("rsvg-convert"); err != nil {
		return fmt.Errorf("rsvg-convert unavailable: %w", err)
	}
	return nil
}

func ensurePDFFileName(name string) string {
	base := strings.TrimSpace(filepath.Base(name))
	if base == "" || base == "." || base == string(filepath.Separator) {
		return "i9-supporting-document.pdf"
	}
	ext := strings.ToLower(strings.TrimSpace(filepath.Ext(base)))
	base = strings.TrimSuffix(base, ext)
	base = strings.TrimSpace(base)
	if base == "" {
		base = "i9-supporting-document"
	}
	return base + ".pdf"
}

func stampDrawnSignatureOnPDF(pdfData, signatureData []byte, placement signaturePlacement) ([]byte, error) {
	if len(pdfData) == 0 {
		return nil, errors.New("generated pdf is empty")
	}
	if len(signatureData) == 0 {
		return nil, errors.New("drawn signature is required")
	}
	if err := ensureTool("rsvg-convert"); err != nil {
		return nil, errors.New("unable to install or find rsvg-convert for signature stamping")
	}
	if placement.Page < 1 {
		return nil, errors.New("invalid signature page")
	}

	tmpDir, err := os.MkdirTemp("", "cfasuite-signature-stamp-*")
	if err != nil {
		return nil, errors.New("unable to prepare signature stamping")
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	inPath := filepath.Join(tmpDir, "in.pdf")
	outPath := filepath.Join(tmpDir, "out.pdf")
	sigSVGPath := filepath.Join(tmpDir, "signature.svg")
	sigStampPath := filepath.Join(tmpDir, "signature-stamp.pdf")
	if err := os.WriteFile(inPath, pdfData, 0o600); err != nil {
		return nil, errors.New("unable to stage generated pdf")
	}
	pageDims, err := api.PageDimsFile(inPath)
	if err != nil {
		return nil, errors.New("unable to read generated pdf page size")
	}
	if placement.Page > len(pageDims) {
		return nil, errors.New("signature page is outside generated pdf")
	}
	pageWidth := pageDims[placement.Page-1].Width
	pageHeight := pageDims[placement.Page-1].Height

	boxWidth := placement.BottomRightX - placement.TopLeftX
	boxHeight := placement.BottomRightY - placement.TopLeftY
	if boxWidth <= 0 || boxHeight <= 0 {
		return nil, errors.New("invalid signature box dimensions")
	}
	if placement.TopLeftX < 0 ||
		placement.TopLeftY < 0 ||
		placement.BottomRightX > pageWidth ||
		placement.BottomRightY > pageHeight {
		return nil, errors.New("signature box exceeds page bounds")
	}
	preparedSig, err := prepareSignatureImage(signatureData)
	if err != nil {
		return nil, err
	}
	preparedBounds := preparedSig.Bounds()
	imgW := float64(preparedBounds.Dx())
	imgH := float64(preparedBounds.Dy())
	if imgW <= 0 || imgH <= 0 {
		return nil, errors.New("drawn signature image is empty")
	}
	scale := math.Min(boxWidth/imgW, boxHeight/imgH)
	fitW := imgW * scale
	fitH := imgH * scale
	if fitW <= 0 || fitH <= 0 {
		return nil, errors.New("invalid signature image dimensions")
	}
	svgData, err := imageToSVG(preparedSig, fitW, fitH)
	if err != nil {
		return nil, errors.New("unable to prepare signature overlay")
	}
	if err := os.WriteFile(sigSVGPath, svgData, 0o600); err != nil {
		return nil, errors.New("unable to stage signature overlay")
	}

	// Best-effort cleanup for signature form fields that can render above the image stamp.
	if pdfcpuPath, resolveErr := resolvePdfcpuPath(); resolveErr == nil {
		fieldNames := make([]string, 0, 3)
		appendFieldName := func(raw string) {
			for _, part := range strings.Split(raw, ",") {
				name := strings.TrimSpace(part)
				if name == "" {
					continue
				}
				for _, existing := range fieldNames {
					if strings.EqualFold(existing, name) {
						return
					}
				}
				fieldNames = append(fieldNames, name)
			}
		}
		appendFieldName(placement.FormFieldName)
		appendFieldName("signature")
		appendFieldName("signature_box")
		for _, fieldName := range fieldNames {
			cleanPath := filepath.Join(tmpDir, "clean.pdf")
			cleanCtx, cleanCancel := context.WithTimeout(context.Background(), 8*time.Second)
			output, cleanErr := exec.CommandContext(cleanCtx, pdfcpuPath,
				"form", "remove", inPath, cleanPath, fieldName,
			).CombinedOutput()
			cleanCancel()
			if cleanErr != nil {
				outText := strings.TrimSpace(string(output))
				if strings.Contains(strings.ToLower(outText), "no form fields affected") ||
					strings.Contains(strings.ToLower(outText), "unable to resolve field id/name") {
					// Not all templates have both candidate field names.
					continue
				}
				log.Printf("warning: unable to remove signature field %q before stamping: %s", fieldName, outText)
				continue
			}
			cleanData, readErr := os.ReadFile(cleanPath)
			if readErr != nil || len(cleanData) == 0 {
				log.Printf("warning: unable to read cleaned pdf after removing signature field %q: %v", fieldName, readErr)
				continue
			}
			if writeErr := os.WriteFile(inPath, cleanData, 0o600); writeErr != nil {
				log.Printf("warning: unable to stage cleaned pdf for signature stamp: %v", writeErr)
				continue
			}
		}
	} else {
		log.Printf("warning: pdfcpu CLI unavailable for pre-stamp cleanup: %v", resolveErr)
	}

	nativeDPIX := math.Max(72, math.Round(imgW*72/fitW))
	nativeDPIY := math.Max(72, math.Round(imgH*72/fitH))
	rsvgCtx, rsvgCancel := context.WithTimeout(context.Background(), 12*time.Second)
	rsvgCmd := exec.CommandContext(
		rsvgCtx,
		"rsvg-convert",
		"-f", "pdf",
		"--dpi-x", fmt.Sprintf("%.0f", nativeDPIX),
		"--dpi-y", fmt.Sprintf("%.0f", nativeDPIY),
		"-o", sigStampPath,
		sigSVGPath,
	)
	rsvgOutput, rsvgErr := rsvgCmd.CombinedOutput()
	rsvgCancel()
	if rsvgErr != nil {
		return nil, fmt.Errorf("unable to convert signature overlay: %s", strings.TrimSpace(string(rsvgOutput)))
	}

	offsetX := (boxWidth - fitW) / 2
	offsetY := (boxHeight - fitH) / 2
	pdfX := placement.TopLeftX + offsetX
	pdfY := pageHeight - placement.BottomRightY + offsetY
	desc := fmt.Sprintf(
		"position:bl, offset:%0.4f %0.4f, scalefactor:1 abs, opacity:1, rotation:0",
		pdfX,
		pdfY,
	)

	wm, err := api.PDFWatermark(sigStampPath, desc, true, false, types.POINTS)
	if err != nil {
		return nil, fmt.Errorf("unable to prepare signature watermark: %v", err)
	}
	if err := api.AddWatermarksFile(inPath, outPath, []string{strconv.Itoa(placement.Page)}, wm, nil); err != nil {
		return nil, fmt.Errorf("unable to place drawn signature: %v", err)
	}

	stampedPDF, err := os.ReadFile(outPath)
	if err != nil {
		return nil, errors.New("unable to read stamped pdf")
	}
	if len(stampedPDF) == 0 {
		return nil, errors.New("stamped pdf is empty")
	}
	return stampedPDF, nil
}

func prepareSignatureImage(signatureData []byte) (image.Image, error) {
	src, err := decodeImageWithWebPFallback(signatureData)
	if err != nil {
		return nil, errors.New("unable to decode drawn signature")
	}
	// Normalize ink: force all opaque/semi-opaque pixels to dark ink so signatures drawn
	// in dark-mode browsers (where the CSS ink variable is near-white) appear on white PDF.
	src = normalizeSignatureInkColor(src)
	cropRect := detectSignatureBounds(src)
	if cropRect.Empty() {
		cropRect = src.Bounds()
	}
	cropped := image.NewNRGBA(image.Rect(0, 0, cropRect.Dx(), cropRect.Dy()))
	stddraw.Draw(cropped, cropped.Bounds(), src, cropRect.Min, stddraw.Src)
	return cropped, nil
}

func imageToSVG(img image.Image, svgWidthPt, svgHeightPt float64) ([]byte, error) {
	bounds := img.Bounds()
	imgW := bounds.Dx()
	imgH := bounds.Dy()
	var out bytes.Buffer
	if err := png.Encode(&out, img); err != nil {
		return nil, fmt.Errorf("encode png for signature overlay: %w", err)
	}
	if out.Len() == 0 || imgW <= 0 || imgH <= 0 {
		return nil, errors.New("drawn signature image is empty")
	}
	b64 := base64.StdEncoding.EncodeToString(out.Bytes())
	svg := fmt.Sprintf(
		`<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg"
     xmlns:xlink="http://www.w3.org/1999/xlink"
     width="%.6fpt" height="%.6fpt"
     viewBox="0 0 %d %d">
  <image x="0" y="0" width="%d" height="%d"
         preserveAspectRatio="none"
         xlink:href="data:image/png;base64,%s"/>
</svg>`,
		svgWidthPt, svgHeightPt,
		imgW, imgH,
		imgW, imgH,
		b64,
	)
	return []byte(svg), nil
}

func decodeImageWithWebPFallback(raw []byte) (image.Image, error) {
	img, _, err := image.Decode(bytes.NewReader(raw))
	if err == nil {
		return img, nil
	}
	if decoded, webpErr := webp.Decode(bytes.NewReader(raw)); webpErr == nil {
		return decoded, nil
	}
	return nil, err
}

func detectSignatureBounds(img image.Image) image.Rectangle {
	bounds := img.Bounds()
	minX, minY := bounds.Max.X, bounds.Max.Y
	maxX, maxY := bounds.Min.X, bounds.Min.Y
	found := false
	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
		for x := bounds.Min.X; x < bounds.Max.X; x++ {
			r, g, b, a := img.At(x, y).RGBA()
			if a == 0 {
				continue
			}
			// Ignore near-white pixels so anti-aliased canvas backgrounds do not bloat bounds.
			if r > 0xf000 && g > 0xf000 && b > 0xf000 {
				continue
			}
			if x < minX {
				minX = x
			}
			if y < minY {
				minY = y
			}
			if x > maxX {
				maxX = x
			}
			if y > maxY {
				maxY = y
			}
			found = true
		}
	}
	if !found {
		return image.Rectangle{}
	}
	return image.Rect(minX, minY, maxX+1, maxY+1)
}

// normalizeSignatureInkColor converts all opaque/semi-opaque pixels in a signature
// image to a standard dark ink color (#1f232a), preserving their alpha values.
// This ensures signatures drawn with a light ink color (e.g. from dark-mode browsers)
// are always visible when stamped onto a white PDF background.
func normalizeSignatureInkColor(src image.Image) image.Image {
	const (
		inkR = 31
		inkG = 35
		inkB = 42
	)
	bounds := src.Bounds()
	dst := image.NewNRGBA(bounds)
	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
		for x := bounds.Min.X; x < bounds.Max.X; x++ {
			_, _, _, a := src.At(x, y).RGBA()
			if a == 0 {
				continue
			}
			dst.SetNRGBA(x, y, color.NRGBA{R: inkR, G: inkG, B: inkB, A: uint8(a >> 8)})
		}
	}
	return dst
}

func normalizeUSStateCode(value string) string {
	key := strings.ToUpper(strings.TrimSpace(value))
	if key == "" {
		return ""
	}
	stateByName := map[string]string{
		"ALABAMA":                  "AL",
		"ALASKA":                   "AK",
		"ARIZONA":                  "AZ",
		"ARKANSAS":                 "AR",
		"CALIFORNIA":               "CA",
		"COLORADO":                 "CO",
		"CONNECTICUT":              "CT",
		"DELAWARE":                 "DE",
		"DISTRICT OF COLUMBIA":     "DC",
		"FLORIDA":                  "FL",
		"GEORGIA":                  "GA",
		"HAWAII":                   "HI",
		"IDAHO":                    "ID",
		"ILLINOIS":                 "IL",
		"INDIANA":                  "IN",
		"IOWA":                     "IA",
		"KANSAS":                   "KS",
		"KENTUCKY":                 "KY",
		"LOUISIANA":                "LA",
		"MAINE":                    "ME",
		"MARYLAND":                 "MD",
		"MASSACHUSETTS":            "MA",
		"MICHIGAN":                 "MI",
		"MINNESOTA":                "MN",
		"MISSISSIPPI":              "MS",
		"MISSOURI":                 "MO",
		"MONTANA":                  "MT",
		"NEBRASKA":                 "NE",
		"NEVADA":                   "NV",
		"NEW HAMPSHIRE":            "NH",
		"NEW JERSEY":               "NJ",
		"NEW MEXICO":               "NM",
		"NEW YORK":                 "NY",
		"NORTH CAROLINA":           "NC",
		"NORTH DAKOTA":             "ND",
		"OHIO":                     "OH",
		"OKLAHOMA":                 "OK",
		"OREGON":                   "OR",
		"PENNSYLVANIA":             "PA",
		"RHODE ISLAND":             "RI",
		"SOUTH CAROLINA":           "SC",
		"SOUTH DAKOTA":             "SD",
		"TENNESSEE":                "TN",
		"TEXAS":                    "TX",
		"UTAH":                     "UT",
		"VERMONT":                  "VT",
		"VIRGINIA":                 "VA",
		"WASHINGTON":               "WA",
		"WEST VIRGINIA":            "WV",
		"WISCONSIN":                "WI",
		"WYOMING":                  "WY",
		"AMERICAN SAMOA":           "AS",
		"GUAM":                     "GU",
		"NORTHERN MARIANA ISLANDS": "MP",
		"PUERTO RICO":              "PR",
		"US VIRGIN ISLANDS":        "VI",
		"U.S. VIRGIN ISLANDS":      "VI",
		"VIRGIN ISLANDS":           "VI",
		"CANADA":                   "CAN",
		"MEXICO":                   "MEX",
	}
	validCodes := map[string]struct{}{
		"AK": {}, "AL": {}, "AR": {}, "AS": {}, "AZ": {}, "CA": {}, "CO": {}, "CT": {}, "DC": {}, "DE": {},
		"FL": {}, "GA": {}, "GU": {}, "HI": {}, "IA": {}, "ID": {}, "IL": {}, "IN": {}, "KS": {}, "KY": {},
		"LA": {}, "MA": {}, "MD": {}, "ME": {}, "MI": {}, "MN": {}, "MO": {}, "MP": {}, "MS": {}, "MT": {},
		"NC": {}, "ND": {}, "NE": {}, "NH": {}, "NJ": {}, "NM": {}, "NV": {}, "NY": {}, "OH": {}, "OK": {},
		"OR": {}, "PA": {}, "PR": {}, "RI": {}, "SC": {}, "SD": {}, "TN": {}, "TX": {}, "UT": {}, "VA": {},
		"VI": {}, "VT": {}, "WA": {}, "WI": {}, "WV": {}, "WY": {}, "CAN": {}, "MEX": {},
	}
	if _, ok := validCodes[key]; ok {
		return key
	}
	key = strings.ReplaceAll(key, ".", "")
	key = strings.Join(strings.Fields(key), " ")
	if _, ok := validCodes[key]; ok {
		return key
	}
	compact := strings.Map(func(r rune) rune {
		if r >= 'A' && r <= 'Z' {
			return r
		}
		return -1
	}, key)
	if _, ok := validCodes[compact]; ok {
		return compact
	}
	if mapped, ok := stateByName[key]; ok {
		return mapped
	}
	compactNameMap := map[string]string{
		"DISTRICTOFCOLUMBIA":     "DC",
		"NORTHCAROLINA":          "NC",
		"NORTHDAKOTA":            "ND",
		"SOUTHCAROLINA":          "SC",
		"SOUTHDAKOTA":            "SD",
		"NEWHAMPSHIRE":           "NH",
		"NEWJERSEY":              "NJ",
		"NEWMEXICO":              "NM",
		"NEWYORK":                "NY",
		"WESTVIRGINIA":           "WV",
		"NORTHERNMARIANAISLANDS": "MP",
		"AMERICANSAMOA":          "AS",
		"PUERTORICO":             "PR",
		"USVIRGINISLANDS":        "VI",
		"UVIRGINISLANDS":         "VI",
		"VIRGINISLANDS":          "VI",
	}
	if mapped, ok := compactNameMap[compact]; ok {
		return mapped
	}
	return ""
}

func paperworkEmployeePatchFromForm(existing *employee, form url.Values) (*employee, error) {
	if existing == nil {
		return nil, errors.New("employee not found")
	}
	updated := *existing
	dob := strings.TrimSpace(form.Get("date_of_birth"))
	if dob != "" {
		normalized, ok := normalizeBirthday(dob)
		if !ok {
			return nil, errors.New("date of birth must be a valid date")
		}
		updated.Birthday = normalized
	}

	email := strings.TrimSpace(form.Get("email"))
	if email == "" {
		return nil, errors.New("email is required")
	}
	if len([]rune(email)) > 200 {
		return nil, errors.New("email must be 200 characters or fewer")
	}
	if parsed, err := mail.ParseAddress(email); err != nil || strings.TrimSpace(parsed.Address) != email {
		return nil, errors.New("email must be a valid email address")
	}

	phoneDigits := strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, form.Get("phone"))
	if len(phoneDigits) != 10 {
		return nil, errors.New("phone must contain exactly 10 digits")
	}
	phone := phoneDigits[0:3] + "-" + phoneDigits[3:6] + "-" + phoneDigits[6:10]

	address := strings.TrimSpace(form.Get("address"))
	if address == "" {
		return nil, errors.New("address is required")
	}
	if len([]rune(address)) > 180 {
		return nil, errors.New("address must be 180 characters or fewer")
	}

	aptNumber := strings.TrimSpace(form.Get("apt_number"))
	if len([]rune(aptNumber)) > 40 {
		return nil, errors.New("apt number must be 40 characters or fewer")
	}

	city := strings.ToUpper(strings.TrimSpace(form.Get("city")))
	city = strings.Join(strings.Fields(city), " ")
	if city == "" {
		return nil, errors.New("city is required")
	}
	if !cityPattern.MatchString(city) {
		return nil, errors.New("city must use letters and standard punctuation only")
	}

	state := normalizeUSStateCode(form.Get("state"))
	if state == "" {
		return nil, errors.New("state must be a valid US state or territory")
	}

	zipCode := strings.TrimSpace(form.Get("zip_code"))
	if !zipCodePattern.MatchString(zipCode) {
		return nil, errors.New("zip code must be 5 digits or ZIP+4 (e.g. 12345 or 12345-6789)")
	}

	updated.Email = email
	updated.Phone = phone
	updated.Address = address
	updated.AptNumber = aptNumber
	updated.City = city
	updated.State = state
	updated.ZipCode = zipCode
	return &updated, nil
}

func (s *sqliteStore) hasEmployeePaperworkSubmission(ctx context.Context, locationNumber, timePunchName string) (bool, error) {
	rows, err := s.query(ctx, `
		SELECT
			EXISTS(
				SELECT 1 FROM employee_i9_forms
				WHERE location_number = @location_number
					AND time_punch_name = @time_punch_name
					AND TRIM(COALESCE(file_data, '')) <> ''
			) AS has_i9,
			EXISTS(
				SELECT 1 FROM employee_w4_forms
				WHERE location_number = @location_number
					AND time_punch_name = @time_punch_name
					AND TRIM(COALESCE(file_data, '')) <> ''
			) AS has_w4;
	`, map[string]string{
		"location_number": locationNumber,
		"time_punch_name": timePunchName,
	})
	if err != nil {
		return false, err
	}
	if len(rows) == 0 {
		return false, nil
	}
	hasI9Int, err := valueAsInt64(rows[0]["has_i9"])
	if err != nil {
		return false, err
	}
	hasW4Int, err := valueAsInt64(rows[0]["has_w4"])
	if err != nil {
		return false, err
	}
	return hasI9Int > 0 && hasW4Int > 0, nil
}

func (s *sqliteStore) getDocumentTemplateByType(ctx context.Context, documentType string) (documentTemplate, error) {
	rows, err := s.query(ctx, `
		SELECT
			id, document_type, template_path, signature_page, signature_top_left_x, signature_top_left_y,
			signature_width, signature_height, signature_zoom, form_field_name, created_at, updated_at
		FROM document_templates
		WHERE document_type = @document_type
		LIMIT 1;
	`, map[string]string{
		"document_type": strings.ToLower(strings.TrimSpace(documentType)),
	})
	if err != nil {
		return documentTemplate{}, err
	}
	if len(rows) == 0 {
		return documentTemplate{}, errNotFound
	}
	id, err := valueAsInt64(rows[0]["id"])
	if err != nil {
		return documentTemplate{}, err
	}
	sigPage, err := valueAsInt64(rows[0]["signature_page"])
	if err != nil {
		return documentTemplate{}, err
	}
	topLeftX, err := valueAsFloat64(rows[0]["signature_top_left_x"])
	if err != nil {
		return documentTemplate{}, err
	}
	topLeftY, err := valueAsFloat64(rows[0]["signature_top_left_y"])
	if err != nil {
		return documentTemplate{}, err
	}
	sigWidth, err := valueAsFloat64(rows[0]["signature_width"])
	if err != nil {
		return documentTemplate{}, err
	}
	sigHeight, err := valueAsFloat64(rows[0]["signature_height"])
	if err != nil {
		return documentTemplate{}, err
	}
	sigZoom, err := valueAsInt64(rows[0]["signature_zoom"])
	if err != nil {
		return documentTemplate{}, err
	}
	createdAtUnix, err := valueAsInt64(rows[0]["created_at"])
	if err != nil {
		return documentTemplate{}, err
	}
	updatedAtUnix, err := valueAsInt64(rows[0]["updated_at"])
	if err != nil {
		return documentTemplate{}, err
	}
	docType, err := valueAsString(rows[0]["document_type"])
	if err != nil {
		return documentTemplate{}, err
	}
	templatePath, err := valueAsString(rows[0]["template_path"])
	if err != nil {
		return documentTemplate{}, err
	}
	formFieldName, err := valueAsString(rows[0]["form_field_name"])
	if err != nil {
		return documentTemplate{}, err
	}
	return documentTemplate{
		ID:                id,
		DocumentType:      docType,
		TemplatePath:      templatePath,
		SignaturePage:     int(sigPage),
		SignatureTopLeftX: topLeftX,
		SignatureTopLeftY: topLeftY,
		SignatureWidth:    sigWidth,
		SignatureHeight:   sigHeight,
		SignatureZoom:     int(sigZoom),
		FormFieldName:     formFieldName,
		CreatedAt:         time.Unix(createdAtUnix, 0).UTC(),
		UpdatedAt:         time.Unix(updatedAtUnix, 0).UTC(),
	}, nil
}

func (s *sqliteStore) getOrCreateActiveEmployeePacket(ctx context.Context, locationNumber, timePunchName string) (employeeDocumentPacket, error) {
	rows, err := s.query(ctx, `
		SELECT id, location_number, time_punch_name, status, finalized_at, created_at, updated_at
		FROM employee_document_packets
		WHERE location_number = @location_number
			AND time_punch_name = @time_punch_name
			AND status != 'finalized'
		ORDER BY id DESC
		LIMIT 1;
	`, map[string]string{
		"location_number": locationNumber,
		"time_punch_name": timePunchName,
	})
	if err != nil {
		return employeeDocumentPacket{}, err
	}
	if len(rows) == 0 {
		now := strconv.FormatInt(time.Now().UTC().Unix(), 10)
		if _, err := s.exec(ctx, `
			INSERT INTO employee_document_packets (
				location_number, time_punch_name, status, finalized_at, created_at, updated_at
			)
			VALUES (@location_number, @time_punch_name, 'draft', 0, @created_at, @updated_at);
		`, map[string]string{
			"location_number": locationNumber,
			"time_punch_name": timePunchName,
			"created_at":      now,
			"updated_at":      now,
		}); err != nil {
			return employeeDocumentPacket{}, err
		}
		rows, err = s.query(ctx, `
			SELECT id, location_number, time_punch_name, status, finalized_at, created_at, updated_at
			FROM employee_document_packets
			WHERE location_number = @location_number
				AND time_punch_name = @time_punch_name
				AND status != 'finalized'
			ORDER BY id DESC
			LIMIT 1;
		`, map[string]string{
			"location_number": locationNumber,
			"time_punch_name": timePunchName,
		})
		if err != nil {
			return employeeDocumentPacket{}, err
		}
		if len(rows) == 0 {
			return employeeDocumentPacket{}, errNotFound
		}
	}
	return hydratePacketRow(rows[0])
}

func hydratePacketRow(row map[string]any) (employeeDocumentPacket, error) {
	id, err := valueAsInt64(row["id"])
	if err != nil {
		return employeeDocumentPacket{}, err
	}
	locationNumber, err := valueAsString(row["location_number"])
	if err != nil {
		return employeeDocumentPacket{}, err
	}
	timePunchName, err := valueAsString(row["time_punch_name"])
	if err != nil {
		return employeeDocumentPacket{}, err
	}
	status, err := valueAsString(row["status"])
	if err != nil {
		return employeeDocumentPacket{}, err
	}
	finalizedAtUnix, err := valueAsInt64(row["finalized_at"])
	if err != nil {
		return employeeDocumentPacket{}, err
	}
	createdAtUnix, err := valueAsInt64(row["created_at"])
	if err != nil {
		return employeeDocumentPacket{}, err
	}
	updatedAtUnix, err := valueAsInt64(row["updated_at"])
	if err != nil {
		return employeeDocumentPacket{}, err
	}
	packet := employeeDocumentPacket{
		ID:             id,
		LocationNumber: locationNumber,
		TimePunchName:  timePunchName,
		Status:         status,
		CreatedAt:      time.Unix(createdAtUnix, 0).UTC(),
		UpdatedAt:      time.Unix(updatedAtUnix, 0).UTC(),
	}
	if finalizedAtUnix > 0 {
		packet.FinalizedAt = time.Unix(finalizedAtUnix, 0).UTC()
	}
	return packet, nil
}

func (s *sqliteStore) getPacketByIDForEmployee(ctx context.Context, packetID int64, locationNumber, timePunchName string) (employeeDocumentPacket, error) {
	rows, err := s.query(ctx, `
		SELECT id, location_number, time_punch_name, status, finalized_at, created_at, updated_at
		FROM employee_document_packets
		WHERE id = @id
			AND location_number = @location_number
			AND time_punch_name = @time_punch_name
		LIMIT 1;
	`, map[string]string{
		"id":              strconv.FormatInt(packetID, 10),
		"location_number": locationNumber,
		"time_punch_name": timePunchName,
	})
	if err != nil {
		return employeeDocumentPacket{}, err
	}
	if len(rows) == 0 {
		return employeeDocumentPacket{}, errNotFound
	}
	return hydratePacketRow(rows[0])
}

func (s *sqliteStore) updatePacketStatus(ctx context.Context, packetID int64, status string, finalized bool) error {
	trimmedStatus := strings.TrimSpace(status)
	if trimmedStatus == "" {
		trimmedStatus = "draft"
	}
	now := time.Now().UTC().Unix()
	finalizedAt := int64(0)
	if finalized {
		finalizedAt = now
	}
	_, err := s.exec(ctx, `
		UPDATE employee_document_packets
		SET status = @status,
			finalized_at = CASE WHEN @finalized_at > 0 THEN @finalized_at ELSE finalized_at END,
			updated_at = @updated_at
		WHERE id = @id;
	`, map[string]string{
		"id":           strconv.FormatInt(packetID, 10),
		"status":       trimmedStatus,
		"finalized_at": strconv.FormatInt(finalizedAt, 10),
		"updated_at":   strconv.FormatInt(now, 10),
	})
	return err
}

func (s *sqliteStore) upsertPacketDocument(ctx context.Context, packetID int64, documentType string, template documentTemplate, pdfData []byte, mime, fileName string) error {
	now := strconv.FormatInt(time.Now().UTC().Unix(), 10)
	encoded := base64.StdEncoding.EncodeToString(pdfData)
	_, err := s.exec(ctx, `
		INSERT INTO packet_documents (
			packet_id, document_type, status, file_data, file_mime, file_name,
			signed_file_data, signed_file_mime, signed_file_name,
			signature_page, signature_top_left_x, signature_top_left_y, signature_width, signature_height, signature_zoom, form_field_name,
			required_signatures, signed_count, signed_at, created_at, updated_at
		)
		VALUES (
			@packet_id, @document_type, 'ready_to_sign', @file_data, @file_mime, @file_name,
			'', '', '',
			@signature_page, @signature_top_left_x, @signature_top_left_y, @signature_width, @signature_height, @signature_zoom, @form_field_name,
			1, 0, 0, @created_at, @updated_at
		)
		ON CONFLICT(packet_id, document_type)
		DO UPDATE SET
			status = 'ready_to_sign',
			file_data = excluded.file_data,
			file_mime = excluded.file_mime,
			file_name = excluded.file_name,
			signed_file_data = '',
			signed_file_mime = '',
			signed_file_name = '',
			signature_page = excluded.signature_page,
			signature_top_left_x = excluded.signature_top_left_x,
			signature_top_left_y = excluded.signature_top_left_y,
			signature_width = excluded.signature_width,
			signature_height = excluded.signature_height,
			signature_zoom = excluded.signature_zoom,
			form_field_name = excluded.form_field_name,
			required_signatures = excluded.required_signatures,
			signed_count = 0,
			signed_at = 0,
			updated_at = excluded.updated_at;
	`, map[string]string{
		"packet_id":            strconv.FormatInt(packetID, 10),
		"document_type":        strings.ToLower(strings.TrimSpace(documentType)),
		"file_data":            encoded,
		"file_mime":            strings.TrimSpace(mime),
		"file_name":            strings.TrimSpace(fileName),
		"signature_page":       strconv.Itoa(template.SignaturePage),
		"signature_top_left_x": strconv.FormatFloat(template.SignatureTopLeftX, 'f', 2, 64),
		"signature_top_left_y": strconv.FormatFloat(template.SignatureTopLeftY, 'f', 2, 64),
		"signature_width":      strconv.FormatFloat(template.SignatureWidth, 'f', 2, 64),
		"signature_height":     strconv.FormatFloat(template.SignatureHeight, 'f', 2, 64),
		"signature_zoom":       strconv.Itoa(template.SignatureZoom),
		"form_field_name":      template.FormFieldName,
		"created_at":           now,
		"updated_at":           now,
	})
	return err
}

func hydratePacketDocumentRow(row map[string]any) (packetDocument, error) {
	id, err := valueAsInt64(row["id"])
	if err != nil {
		return packetDocument{}, err
	}
	packetID, err := valueAsInt64(row["packet_id"])
	if err != nil {
		return packetDocument{}, err
	}
	documentType, err := valueAsString(row["document_type"])
	if err != nil {
		return packetDocument{}, err
	}
	status, err := valueAsString(row["status"])
	if err != nil {
		return packetDocument{}, err
	}
	fileDataB64, err := valueAsString(row["file_data"])
	if err != nil {
		return packetDocument{}, err
	}
	fileMime, err := valueAsString(row["file_mime"])
	if err != nil {
		return packetDocument{}, err
	}
	fileName, err := valueAsString(row["file_name"])
	if err != nil {
		return packetDocument{}, err
	}
	signedFileDataB64, err := valueAsString(row["signed_file_data"])
	if err != nil {
		return packetDocument{}, err
	}
	signedFileMime, err := valueAsString(row["signed_file_mime"])
	if err != nil {
		return packetDocument{}, err
	}
	signedFileName, err := valueAsString(row["signed_file_name"])
	if err != nil {
		return packetDocument{}, err
	}
	signaturePage, err := valueAsInt64(row["signature_page"])
	if err != nil {
		return packetDocument{}, err
	}
	signatureTopLeftX, err := valueAsFloat64(row["signature_top_left_x"])
	if err != nil {
		return packetDocument{}, err
	}
	signatureTopLeftY, err := valueAsFloat64(row["signature_top_left_y"])
	if err != nil {
		return packetDocument{}, err
	}
	signatureWidth, err := valueAsFloat64(row["signature_width"])
	if err != nil {
		return packetDocument{}, err
	}
	signatureHeight, err := valueAsFloat64(row["signature_height"])
	if err != nil {
		return packetDocument{}, err
	}
	signatureZoom, err := valueAsInt64(row["signature_zoom"])
	if err != nil {
		return packetDocument{}, err
	}
	formFieldName, err := valueAsString(row["form_field_name"])
	if err != nil {
		return packetDocument{}, err
	}
	requiredSignatures, err := valueAsInt64(row["required_signatures"])
	if err != nil {
		return packetDocument{}, err
	}
	signedCount, err := valueAsInt64(row["signed_count"])
	if err != nil {
		return packetDocument{}, err
	}
	signedAtUnix, err := valueAsInt64(row["signed_at"])
	if err != nil {
		return packetDocument{}, err
	}
	createdAtUnix, err := valueAsInt64(row["created_at"])
	if err != nil {
		return packetDocument{}, err
	}
	updatedAtUnix, err := valueAsInt64(row["updated_at"])
	if err != nil {
		return packetDocument{}, err
	}
	fileData := []byte{}
	if strings.TrimSpace(fileDataB64) != "" {
		fileData, err = base64.StdEncoding.DecodeString(fileDataB64)
		if err != nil {
			return packetDocument{}, err
		}
	}
	signedFileData := []byte{}
	if strings.TrimSpace(signedFileDataB64) != "" {
		signedFileData, err = base64.StdEncoding.DecodeString(signedFileDataB64)
		if err != nil {
			return packetDocument{}, err
		}
	}
	out := packetDocument{
		ID:                 id,
		PacketID:           packetID,
		DocumentType:       documentType,
		Status:             status,
		FileData:           fileData,
		FileMime:           fileMime,
		FileName:           fileName,
		SignedFileData:     signedFileData,
		SignedFileMime:     signedFileMime,
		SignedFileName:     signedFileName,
		SignaturePage:      int(signaturePage),
		SignatureTopLeftX:  signatureTopLeftX,
		SignatureTopLeftY:  signatureTopLeftY,
		SignatureWidth:     signatureWidth,
		SignatureHeight:    signatureHeight,
		SignatureZoom:      int(signatureZoom),
		FormFieldName:      formFieldName,
		RequiredSignatures: requiredSignatures,
		SignedCount:        signedCount,
		CreatedAt:          time.Unix(createdAtUnix, 0).UTC(),
		UpdatedAt:          time.Unix(updatedAtUnix, 0).UTC(),
	}
	if signedAtUnix > 0 {
		out.SignedAt = time.Unix(signedAtUnix, 0).UTC()
	}
	return out, nil
}

func (s *sqliteStore) listPacketDocuments(ctx context.Context, packetID int64) ([]packetDocument, error) {
	rows, err := s.query(ctx, `
		SELECT
			id, packet_id, document_type, status, file_data, file_mime, file_name,
			signed_file_data, signed_file_mime, signed_file_name,
			signature_page, signature_top_left_x, signature_top_left_y, signature_width, signature_height, signature_zoom, form_field_name,
			required_signatures, signed_count, signed_at, created_at, updated_at
		FROM packet_documents
		WHERE packet_id = @packet_id
		ORDER BY CASE LOWER(document_type) WHEN 'i9' THEN 1 WHEN 'w4' THEN 2 ELSE 50 END, id ASC;
	`, map[string]string{
		"packet_id": strconv.FormatInt(packetID, 10),
	})
	if err != nil {
		return nil, err
	}
	out := make([]packetDocument, 0, len(rows))
	for _, row := range rows {
		item, err := hydratePacketDocumentRow(row)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, nil
}

func (s *sqliteStore) getPacketDocumentByType(ctx context.Context, packetID int64, documentType string) (packetDocument, error) {
	rows, err := s.query(ctx, `
		SELECT
			id, packet_id, document_type, status, file_data, file_mime, file_name,
			signed_file_data, signed_file_mime, signed_file_name,
			signature_page, signature_top_left_x, signature_top_left_y, signature_width, signature_height, signature_zoom, form_field_name,
			required_signatures, signed_count, signed_at, created_at, updated_at
		FROM packet_documents
		WHERE packet_id = @packet_id
			AND document_type = @document_type
		LIMIT 1;
	`, map[string]string{
		"packet_id":     strconv.FormatInt(packetID, 10),
		"document_type": strings.ToLower(strings.TrimSpace(documentType)),
	})
	if err != nil {
		return packetDocument{}, err
	}
	if len(rows) == 0 {
		return packetDocument{}, errNotFound
	}
	return hydratePacketDocumentRow(rows[0])
}

func (s *sqliteStore) markPacketDocumentSigned(ctx context.Context, packetDocumentID int64, signedPDF []byte, mime, fileName string) error {
	now := strconv.FormatInt(time.Now().UTC().Unix(), 10)
	encoded := base64.StdEncoding.EncodeToString(signedPDF)
	_, err := s.exec(ctx, `
		UPDATE packet_documents
		SET status = 'signed',
			signed_file_data = @signed_file_data,
			signed_file_mime = @signed_file_mime,
			signed_file_name = @signed_file_name,
			signed_count = required_signatures,
			signed_at = @signed_at,
			updated_at = @updated_at
		WHERE id = @id;
	`, map[string]string{
		"id":               strconv.FormatInt(packetDocumentID, 10),
		"signed_file_data": encoded,
		"signed_file_mime": strings.TrimSpace(mime),
		"signed_file_name": strings.TrimSpace(fileName),
		"signed_at":        now,
		"updated_at":       now,
	})
	return err
}

func (s *sqliteStore) addSignatureEvent(ctx context.Context, packetID, packetDocumentID int64, locationNumber, timePunchName, signerName, signerIP, userAgent, eventType, signatureHash string, signatureIndex int64) error {
	now := strconv.FormatInt(time.Now().UTC().Unix(), 10)
	_, err := s.exec(ctx, `
		INSERT INTO signature_events (
			packet_id, packet_document_id, location_number, time_punch_name, signer_name, signer_ip, user_agent, event_type, signature_index, signature_hash, created_at
		)
		VALUES (
			@packet_id, @packet_document_id, @location_number, @time_punch_name, @signer_name, @signer_ip, @user_agent, @event_type, @signature_index, @signature_hash, @created_at
		);
	`, map[string]string{
		"packet_id":          strconv.FormatInt(packetID, 10),
		"packet_document_id": strconv.FormatInt(packetDocumentID, 10),
		"location_number":    locationNumber,
		"time_punch_name":    timePunchName,
		"signer_name":        strings.TrimSpace(signerName),
		"signer_ip":          strings.TrimSpace(signerIP),
		"user_agent":         strings.TrimSpace(userAgent),
		"event_type":         strings.TrimSpace(eventType),
		"signature_index":    strconv.FormatInt(signatureIndex, 10),
		"signature_hash":     strings.TrimSpace(signatureHash),
		"created_at":         now,
	})
	return err
}

func (s *server) publicTimePunchHandler(w http.ResponseWriter, r *http.Request) {
	trimmed := strings.TrimPrefix(r.URL.Path, "/api/public/time-punch/")
	trimmed = strings.Trim(trimmed, "/")
	if trimmed == "" {
		http.NotFound(w, r)
		return
	}
	token := strings.TrimSpace(trimmed)
	record, err := s.store.getLocationTimePunchToken(r.Context(), token)
	if err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "invalid time punch link")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to validate link")
		return
	}

	switch r.Method {
	case http.MethodGet:
		loc, err := s.store.getLocationByNumber(r.Context(), record.LocationNumber)
		if err != nil {
			if errors.Is(err, errNotFound) {
				writeError(w, http.StatusNotFound, "location not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "unable to load location")
			return
		}
		employees, err := s.store.listLocationEmployees(r.Context(), record.LocationNumber)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "unable to load employees")
			return
		}
		sort.Slice(employees, func(i, j int) bool {
			if employees[i].LastName == employees[j].LastName {
				return employees[i].FirstName < employees[j].FirstName
			}
			return employees[i].LastName < employees[j].LastName
		})
		writeJSON(w, http.StatusOK, map[string]any{
			"locationNumber": record.LocationNumber,
			"locationName":   loc.Name,
			"employees":      employees,
		})
	case http.MethodPost:
		writeError(w, http.StatusForbidden, "team login required")
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *server) publicTimeOffHandler(w http.ResponseWriter, r *http.Request) {
	trimmed := strings.TrimPrefix(r.URL.Path, "/api/public/time-off/")
	trimmed = strings.Trim(trimmed, "/")
	if trimmed == "" {
		http.NotFound(w, r)
		return
	}
	token := strings.TrimSpace(trimmed)
	record, err := s.store.getLocationTimeOffToken(r.Context(), token)
	if err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "invalid time off link")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to validate link")
		return
	}

	switch r.Method {
	case http.MethodGet:
		loc, err := s.store.getLocationByNumber(r.Context(), record.LocationNumber)
		if err != nil {
			if errors.Is(err, errNotFound) {
				writeError(w, http.StatusNotFound, "location not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "unable to load location")
			return
		}
		employees, err := s.store.listLocationEmployees(r.Context(), record.LocationNumber)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "unable to load employees")
			return
		}
		sort.Slice(employees, func(i, j int) bool {
			if employees[i].LastName == employees[j].LastName {
				return employees[i].FirstName < employees[j].FirstName
			}
			return employees[i].LastName < employees[j].LastName
		})
		writeJSON(w, http.StatusOK, map[string]any{
			"locationNumber": record.LocationNumber,
			"locationName":   loc.Name,
			"employees":      employees,
		})
	case http.MethodPost:
		writeError(w, http.StatusForbidden, "team login required")
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *server) publicUniformOrderHandler(w http.ResponseWriter, r *http.Request) {
	trimmed := strings.TrimPrefix(r.URL.Path, "/api/public/uniform-order/")
	trimmed = strings.Trim(trimmed, "/")
	if trimmed == "" {
		http.NotFound(w, r)
		return
	}
	token := strings.TrimSpace(trimmed)
	record, err := s.store.getLocationUniformToken(r.Context(), token)
	if err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "invalid uniform order link")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to validate link")
		return
	}

	switch r.Method {
	case http.MethodGet:
		loc, err := s.store.getLocationByNumber(r.Context(), record.LocationNumber)
		if err != nil {
			if errors.Is(err, errNotFound) {
				writeError(w, http.StatusNotFound, "location not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "unable to load location")
			return
		}
		employees, err := s.store.listLocationEmployees(r.Context(), record.LocationNumber)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "unable to load employees")
			return
		}
		sort.Slice(employees, func(i, j int) bool {
			if employees[i].LastName == employees[j].LastName {
				return employees[i].FirstName < employees[j].FirstName
			}
			return employees[i].LastName < employees[j].LastName
		})
		items, err := s.store.listUniformItems(r.Context(), record.LocationNumber, false)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "unable to load uniform items")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"locationNumber": record.LocationNumber,
			"locationName":   loc.Name,
			"employees":      employees,
			"items":          items,
		})
	case http.MethodPost:
		writeError(w, http.StatusForbidden, "team login required")
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *server) listLocationUniformItems(w http.ResponseWriter, r *http.Request, number string) {
	if _, err := s.store.getLocationByNumber(r.Context(), number); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "location not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load location")
		return
	}
	if _, err := s.ensureLocationShoesItem(r.Context(), number); err != nil {
		writeError(w, http.StatusInternalServerError, "unable to load uniform items")
		return
	}
	items, err := s.store.listUniformItems(r.Context(), number, false)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to load uniform items")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"count": len(items),
		"items": items,
	})
}

func (s *server) getLocationUniformItem(w http.ResponseWriter, r *http.Request, number string, itemID int64) {
	if _, err := s.store.getLocationByNumber(r.Context(), number); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "location not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load location")
		return
	}
	if _, err := s.ensureLocationShoesItem(r.Context(), number); err != nil {
		writeError(w, http.StatusInternalServerError, "unable to load uniform item")
		return
	}
	item, err := s.store.getUniformItemByID(r.Context(), number, itemID)
	if err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "uniform item not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load uniform item")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"item": item})
}

func (s *server) createLocationUniformItem(w http.ResponseWriter, r *http.Request, number string) {
	if _, err := s.store.getLocationByNumber(r.Context(), number); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "location not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load location")
		return
	}

	if err := r.ParseMultipartForm(20 << 20); err != nil {
		writeError(w, http.StatusBadRequest, "invalid upload form")
		return
	}
	req := createUniformItemRequest{
		Name:       strings.TrimSpace(r.FormValue("name")),
		Price:      strings.TrimSpace(r.FormValue("price")),
		Sizes:      strings.TrimSpace(r.FormValue("sizes")),
		SizeFields: strings.TrimSpace(r.FormValue("size_fields")),
	}
	priceCents, err := parsePriceToCents(req.Price)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "item name is required")
		return
	}

	raw, mime, err := parseUploadedPhotoWithField(r, "photo_file")
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	images := []uniformItemImage{
		{
			ImageData: base64.StdEncoding.EncodeToString(raw),
			ImageMime: mime,
			SortOrder: 0,
		},
	}
	sizeFields, err := normalizeUniformSizeFieldsInput(req.SizeFields, req.Sizes)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	sizes := flattenUniformSizeFields(sizeFields)

	item := uniformItem{
		LocationNum: number,
		Name:        req.Name,
		Price:       float64(priceCents) / 100.0,
		Enabled:     true,
		ImageData:   base64.StdEncoding.EncodeToString(raw),
		ImageMime:   mime,
		Images:      images,
		Sizes:       sizes,
		SizeFields:  sizeFields,
		CreatedAt:   time.Now().UTC(),
		UpdatedAt:   time.Now().UTC(),
	}
	err = withSQLiteRetry(func() error {
		return s.store.createUniformItem(r.Context(), item, priceCents, sizeFields)
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to persist uniform item")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"message": "uniform item created"})
}

func (s *server) updateLocationUniformItem(w http.ResponseWriter, r *http.Request, number string, itemID int64) {
	if _, err := s.store.getLocationByNumber(r.Context(), number); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "location not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load location")
		return
	}
	item, err := s.store.getUniformItemByID(r.Context(), number, itemID)
	if err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "uniform item not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load uniform item")
		return
	}
	if strings.EqualFold(strings.TrimSpace(item.SystemKey), uniformSystemKeyShoes) {
		writeError(w, http.StatusForbidden, "system uniform item cannot be edited")
		return
	}
	var req updateUniformItemRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	req.Sizes = strings.TrimSpace(req.Sizes)
	req.SizeFields = strings.TrimSpace(req.SizeFields)
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "item name is required")
		return
	}
	priceCents, err := parsePriceToCents(req.Price)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	sizeFields, err := normalizeUniformSizeFieldsInput(req.SizeFields, req.Sizes)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := withSQLiteRetry(func() error {
		return s.store.updateUniformItem(r.Context(), number, itemID, req.Name, priceCents, sizeFields)
	}); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "uniform item not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to persist uniform item")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "uniform item updated"})
}

func (s *server) deleteLocationUniformItem(w http.ResponseWriter, r *http.Request, number string, itemID int64) {
	if _, err := s.store.getLocationByNumber(r.Context(), number); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "location not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load location")
		return
	}
	item, err := s.store.getUniformItemByID(r.Context(), number, itemID)
	if err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "uniform item not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load uniform item")
		return
	}
	if strings.EqualFold(strings.TrimSpace(item.SystemKey), uniformSystemKeyShoes) {
		writeError(w, http.StatusForbidden, "system uniform item cannot be deleted")
		return
	}
	if err := withSQLiteRetry(func() error {
		return s.store.deleteUniformItem(r.Context(), number, itemID)
	}); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "uniform item not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to delete uniform item")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "uniform item deleted"})
}

func (s *server) createLocationUniformOrder(w http.ResponseWriter, r *http.Request, number string) {
	if _, err := s.store.getLocationByNumber(r.Context(), number); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "location not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load location")
		return
	}
	var req createUniformOrderRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.TimePunchName = strings.TrimSpace(req.TimePunchName)
	if err := validateCreateUniformOrder(req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, err := s.store.getLocationEmployee(r.Context(), number, req.TimePunchName); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusBadRequest, "employee not found for this location")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to validate employee")
		return
	}
	shoesItem, err := s.ensureLocationShoesItem(r.Context(), number)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to prepare shoes item")
		return
	}
	enabledItems, err := s.store.listUniformItems(r.Context(), number, true)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to validate uniform items")
		return
	}
	itemsByID := make(map[int64]uniformItem, len(enabledItems))
	for _, item := range enabledItems {
		itemsByID[item.ID] = item
	}
	itemsByID[shoesItem.ID] = *shoesItem
	lineItems := make([]uniformOrderLineInput, 0, len(req.Items))
	for _, line := range req.Items {
		orderType := strings.ToLower(strings.TrimSpace(line.OrderType))
		if orderType == uniformSystemKeyShoes {
			itemNumber := strings.TrimSpace(line.ShoeItemNumber)
			if !shoeStylePattern.MatchString(itemNumber) {
				writeError(w, http.StatusBadRequest, "shoe style number must be exactly 5 digits")
				return
			}
			baseCents, err := parsePriceToCents(line.ShoePrice)
			if err != nil || baseCents <= 0 {
				writeError(w, http.StatusBadRequest, "shoe price must be greater than 0")
				return
			}
			taxCents := (baseCents*shoeTaxPercent + 50) / 100
			unitCents := baseCents + taxCents + shoeShippingCentsPerItem
			shoeURL := strings.TrimSpace(line.ShoeURL)
			if shoeURL == "" {
				shoeURL = "https://www.shoesforcrews.com/sfc3/index.cfm?changeWebsite=US_en&route=c_store.search&keywords=" + url.QueryEscape(itemNumber)
			}
			lineItems = append(lineItems, uniformOrderLineInput{
				ItemID:         shoesItem.ID,
				ItemName:       shoesItem.Name,
				ItemNumber:     itemNumber,
				Size:           "",
				ExternalURL:    shoeURL,
				Note:           strings.TrimSpace(line.Note),
				Quantity:       line.Quantity,
				UnitPriceCents: unitCents,
			})
			continue
		}
		item, ok := itemsByID[line.ItemID]
		if !ok {
			writeError(w, http.StatusBadRequest, "one or more selected uniform items are invalid")
			return
		}
		if line.Quantity <= 0 {
			writeError(w, http.StatusBadRequest, "quantity must be at least 1")
			return
		}
		rawSelections := normalizeSizeSelections(line.SizeSelections)
		sizeSelections := map[string]string{}
		for _, field := range item.SizeFields {
			label := strings.TrimSpace(field.Label)
			if label == "" {
				continue
			}
			for key, value := range rawSelections {
				if strings.EqualFold(strings.TrimSpace(key), label) {
					sizeSelections[label] = strings.TrimSpace(value)
					break
				}
			}
		}
		sizeValues := normalizeSizeValues(line.SizeValues)
		if len(sizeValues) > 0 && len(item.SizeFields) > 0 {
			limit := len(item.SizeFields)
			if len(sizeValues) < limit {
				limit = len(sizeValues)
			}
			for i := 0; i < limit; i++ {
				label := strings.TrimSpace(item.SizeFields[i].Label)
				value := strings.TrimSpace(sizeValues[i])
				if label == "" || value == "" {
					continue
				}
				if strings.TrimSpace(sizeSelections[label]) != "" {
					continue
				}
				sizeSelections[label] = value
			}
		}
		if len(sizeSelections) == 0 && strings.TrimSpace(line.Size) != "" && len(item.SizeFields) == 1 {
			sizeSelections[item.SizeFields[0].Label] = strings.TrimSpace(line.Size)
		}
		sizeOption, err := buildUniformSizeOption(item.SizeFields, sizeSelections)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		unitCents, err := parsePriceToCents(fmt.Sprintf("%.2f", item.Price))
		if err != nil {
			writeError(w, http.StatusInternalServerError, "unable to calculate item totals")
			return
		}
		lineItems = append(lineItems, uniformOrderLineInput{
			ItemID:         item.ID,
			ItemName:       item.Name,
			Size:           sizeOption,
			ExternalURL:    "",
			Note:           strings.TrimSpace(line.Note),
			Quantity:       line.Quantity,
			UnitPriceCents: unitCents,
		})
	}
	if len(lineItems) == 0 {
		writeError(w, http.StatusBadRequest, "at least one uniform item must be selected")
		return
	}
	if err := withSQLiteRetry(func() error {
		return s.store.createUniformOrder(r.Context(), number, req.TimePunchName, lineItems)
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "unable to save uniform order")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"message": "uniform order submitted"})
}

func (s *server) ensureLocationShoesItem(ctx context.Context, locationNumber string) (*uniformItem, error) {
	imageData, imageMime := loadDeveloperShoesIcon()
	if existing, err := s.store.getUniformItemBySystemKey(ctx, locationNumber, uniformSystemKeyShoes); err == nil && existing != nil {
		if existing.ImageData != imageData || existing.ImageMime != imageMime {
			_, _ = s.store.exec(ctx, `
				UPDATE location_uniform_items
				SET image_data = @image_data,
					image_mime = @image_mime,
					updated_at = @updated_at
				WHERE id = @id
					AND location_number = @location_number;
			`, map[string]string{
				"id":              strconv.FormatInt(existing.ID, 10),
				"location_number": locationNumber,
				"image_data":      imageData,
				"image_mime":      imageMime,
				"updated_at":      strconv.FormatInt(time.Now().UTC().Unix(), 10),
			})
			if updated, getErr := s.store.getUniformItemBySystemKey(ctx, locationNumber, uniformSystemKeyShoes); getErr == nil && updated != nil {
				return updated, nil
			}
		}
		return existing, nil
	}
	now := time.Now().UTC()
	item := uniformItem{
		LocationNum: locationNumber,
		Name:        "Shoes For Crews",
		Price:       0,
		Enabled:     true,
		SystemKey:   uniformSystemKeyShoes,
		ImageData:   imageData,
		ImageMime:   imageMime,
		Images:      []uniformItemImage{},
		Sizes:       nil,
		SizeFields:  nil,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := withSQLiteRetry(func() error {
		return s.store.createUniformItem(ctx, item, 0, nil)
	}); err != nil {
		if existing, getErr := s.store.getUniformItemBySystemKey(ctx, locationNumber, uniformSystemKeyShoes); getErr == nil && existing != nil {
			return existing, nil
		}
		return nil, err
	}
	return s.store.getUniformItemBySystemKey(ctx, locationNumber, uniformSystemKeyShoes)
}

func loadDeveloperShoesIcon() (string, string) {
	paths := []string{
		"internal/clientapp/assets/shoe.svg",
		"assets/shoe.svg",
	}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil || len(data) == 0 {
			continue
		}
		return base64.StdEncoding.EncodeToString(data), "image/svg+xml"
	}
	fallback := `<svg xmlns="http://www.w3.org/2000/svg" width="180" height="180" viewBox="0 0 180 180"><rect width="180" height="180" rx="20" fill="#f4f4f5"/><path d="M22 111c20 0 32-10 41-24l9-13 14 8 20 10c11 6 21 9 34 9h18v23H22z" fill="#111827"/><path d="M51 106h67" stroke="#fff" stroke-width="4" stroke-linecap="round"/></svg>`
	return base64.StdEncoding.EncodeToString([]byte(fallback)), "image/svg+xml"
}

func (s *server) moveLocationUniformItemImage(w http.ResponseWriter, r *http.Request, number string, itemID, imageID int64) {
	if _, err := s.store.getLocationByNumber(r.Context(), number); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "location not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load location")
		return
	}
	item, err := s.store.getUniformItemByID(r.Context(), number, itemID)
	if err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "uniform item not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load uniform item")
		return
	}
	if strings.EqualFold(strings.TrimSpace(item.SystemKey), uniformSystemKeyShoes) {
		writeError(w, http.StatusForbidden, "system uniform item image cannot be edited")
		return
	}
	var req moveUniformImageRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	direction := strings.ToLower(strings.TrimSpace(req.Direction))
	if direction != "up" && direction != "down" {
		writeError(w, http.StatusBadRequest, "direction must be up or down")
		return
	}
	if err := withSQLiteRetry(func() error {
		return s.store.moveUniformItemImage(r.Context(), number, itemID, imageID, direction)
	}); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "uniform image not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to reorder uniform image")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "uniform image reordered"})
}

func (s *server) addLocationUniformItemImages(w http.ResponseWriter, r *http.Request, number string, itemID int64) {
	if _, err := s.store.getLocationByNumber(r.Context(), number); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "location not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load location")
		return
	}
	item, err := s.store.getUniformItemByID(r.Context(), number, itemID)
	if err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "uniform item not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load uniform item")
		return
	}
	if strings.EqualFold(strings.TrimSpace(item.SystemKey), uniformSystemKeyShoes) {
		writeError(w, http.StatusForbidden, "system uniform item image cannot be edited")
		return
	}
	if err := r.ParseMultipartForm(24 << 20); err != nil {
		writeError(w, http.StatusBadRequest, "invalid upload form")
		return
	}
	images := make([]uniformItemImage, 0, 1)
	croppedRaw, croppedMime, err := parseUploadedPhotoWithField(r, "photo_file")
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	images = append(images, uniformItemImage{
		ImageData: base64.StdEncoding.EncodeToString(croppedRaw),
		ImageMime: croppedMime,
	})
	if err := withSQLiteRetry(func() error {
		return s.store.appendUniformItemImages(r.Context(), number, itemID, images)
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "unable to add gallery images")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "gallery images added"})
}

func (s *server) deleteLocationUniformItemImage(w http.ResponseWriter, r *http.Request, number string, itemID, imageID int64) {
	if _, err := s.store.getLocationByNumber(r.Context(), number); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "location not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load location")
		return
	}
	item, err := s.store.getUniformItemByID(r.Context(), number, itemID)
	if err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "uniform item not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load uniform item")
		return
	}
	if strings.EqualFold(strings.TrimSpace(item.SystemKey), uniformSystemKeyShoes) {
		writeError(w, http.StatusForbidden, "system uniform item image cannot be edited")
		return
	}
	if err := withSQLiteRetry(func() error {
		return s.store.deleteUniformItemImage(r.Context(), number, itemID, imageID)
	}); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "uniform image not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to delete uniform image")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "uniform image deleted"})
}

func (s *server) listLocationUniformOrders(w http.ResponseWriter, r *http.Request, number string) {
	if _, err := s.store.getLocationByNumber(r.Context(), number); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "location not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load location")
		return
	}
	includeArchived := parseBoolQueryValue(r.URL.Query().Get("archived"))
	orders, err := s.store.listUniformOrders(r.Context(), number, includeArchived)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to load uniform orders")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"count":  len(orders),
		"orders": orders,
	})
}

func (s *server) archiveLocationUniformOrder(w http.ResponseWriter, r *http.Request, number string, orderID int64) {
	if _, err := s.store.getLocationByNumber(r.Context(), number); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "location not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load location")
		return
	}
	if err := withSQLiteRetry(func() error {
		return s.store.archiveUniformOrder(r.Context(), number, orderID)
	}); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "uniform order not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to archive uniform order")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "uniform order archived"})
}

func (s *server) updateLocationUniformOrderLineSettlement(w http.ResponseWriter, r *http.Request, number string, orderID, lineID int64) {
	if _, err := s.store.getLocationByNumber(r.Context(), number); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "location not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load location")
		return
	}

	var req updateUniformOrderLineSettlementRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	chargedBackCents := int64(0)
	if strings.TrimSpace(req.ChargedBack) != "" {
		var err error
		chargedBackCents, err = parsePriceToCents(req.ChargedBack)
		if err != nil {
			writeError(w, http.StatusBadRequest, "charged back amount must be a non-negative number")
			return
		}
	}

	autoArchived := false
	err := withSQLiteRetry(func() error {
		var updateErr error
		autoArchived, updateErr = s.store.updateUniformOrderLineSettlement(
			r.Context(),
			number,
			orderID,
			lineID,
			req.Purchased,
			chargedBackCents,
		)
		return updateErr
	})
	if err != nil {
		switch {
		case errors.Is(err, errNotFound):
			writeError(w, http.StatusNotFound, "uniform order line not found")
		default:
			writeError(w, http.StatusBadRequest, err.Error())
		}
		return
	}

	message := "uniform line updated"
	if autoArchived {
		message = "uniform line updated and order archived"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"message":      message,
		"autoArchived": autoArchived,
	})
}

func (s *server) deleteArchivedLocationUniformOrder(w http.ResponseWriter, r *http.Request, number string, orderID int64) {
	if _, err := s.store.getLocationByNumber(r.Context(), number); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "location not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load location")
		return
	}
	if err := withSQLiteRetry(func() error {
		return s.store.deleteArchivedUniformOrder(r.Context(), number, orderID)
	}); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "archived uniform order not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to delete archived uniform order")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "archived uniform order deleted"})
}

func (s *server) getLocationUniformOrderLink(w http.ResponseWriter, r *http.Request, number string) {
	if _, err := s.store.getLocationByNumber(r.Context(), number); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "location not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load location")
		return
	}
	token, err := s.store.getOrCreateLocationUniformToken(r.Context(), number)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to create uniform order link")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"token": token})
}

func (s *server) getLocationByNumber(w http.ResponseWriter, r *http.Request, number string) {
	loc, err := s.store.getLocationByNumber(r.Context(), number)
	if err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "location not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load location")
		return
	}
	employeeCount, err := s.store.countEmployeesForLocation(r.Context(), number)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to load location")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"location":      loc,
		"employeeCount": employeeCount,
	})
}

func (s *server) listLocationEmployees(w http.ResponseWriter, r *http.Request, number string) {
	if _, err := s.store.getLocationByNumber(r.Context(), number); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "location not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load employees")
		return
	}
	employees, err := s.store.listLocationEmployees(r.Context(), number)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to load employees")
		return
	}
	sort.Slice(employees, func(i, j int) bool {
		if employees[i].LastName == employees[j].LastName {
			return employees[i].FirstName < employees[j].FirstName
		}
		return employees[i].LastName < employees[j].LastName
	})

	writeJSON(w, http.StatusOK, map[string]any{
		"count":     len(employees),
		"employees": employees,
	})
}

func (s *server) getLocationSettings(w http.ResponseWriter, r *http.Request, number string) {
	if _, err := s.store.getLocationByNumber(r.Context(), number); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "location not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load location")
		return
	}
	settings, err := s.store.getLocationSettings(r.Context(), number)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to load location settings")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"settings": settings})
}

func (s *server) updateLocationSettings(w http.ResponseWriter, r *http.Request, number string) {
	if _, err := s.store.getLocationByNumber(r.Context(), number); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "location not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load location")
		return
	}
	var req struct {
		EmployerRepSignature string   `json:"employerRepSignature"`
		BusinessName         string   `json:"businessName"`
		BusinessStreet       string   `json:"businessStreet"`
		BusinessCity         string   `json:"businessCity"`
		BusinessState        string   `json:"businessState"`
		BusinessEIN          string   `json:"businessEin"`
		BusinessAddress      string   `json:"businessAddress"`
		W4EmployerName       string   `json:"w4EmployerName"`
		W4EmployerStreet     string   `json:"w4EmployerStreet"`
		W4EmployerCity       string   `json:"w4EmployerCity"`
		W4EmployerState      string   `json:"w4EmployerState"`
		W4EmployerEIN        string   `json:"w4EmployerEin"`
		W4EmployerAddress    string   `json:"w4EmployerAddress"`
		Departments          []string `json:"departments"`
		RestaurantUsername   string   `json:"restaurantUsername"`
		RestaurantPassword   string   `json:"restaurantPassword"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.EmployerRepSignature = strings.TrimSpace(req.EmployerRepSignature)
	req.BusinessName = strings.TrimSpace(req.BusinessName)
	req.BusinessStreet = strings.TrimSpace(req.BusinessStreet)
	req.BusinessCity = strings.TrimSpace(req.BusinessCity)
	req.BusinessState = strings.TrimSpace(req.BusinessState)
	req.BusinessEIN = strings.TrimSpace(req.BusinessEIN)
	req.BusinessAddress = strings.TrimSpace(req.BusinessAddress)
	req.W4EmployerName = strings.TrimSpace(req.W4EmployerName)
	req.W4EmployerStreet = strings.TrimSpace(req.W4EmployerStreet)
	req.W4EmployerCity = strings.TrimSpace(req.W4EmployerCity)
	req.W4EmployerState = strings.TrimSpace(req.W4EmployerState)
	req.W4EmployerEIN = strings.TrimSpace(req.W4EmployerEIN)
	req.W4EmployerAddress = strings.TrimSpace(req.W4EmployerAddress)
	req.RestaurantUsername = strings.TrimSpace(req.RestaurantUsername)
	req.RestaurantPassword = strings.TrimSpace(req.RestaurantPassword)
	currentSettings, err := s.store.getLocationSettings(r.Context(), number)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to load location settings")
		return
	}
	if len(req.EmployerRepSignature) > 120 {
		writeError(w, http.StatusBadRequest, "owner/operator must be 120 characters or fewer")
		return
	}
	if req.BusinessName == "" {
		req.BusinessName = req.W4EmployerName
	}
	if req.BusinessStreet == "" {
		req.BusinessStreet = req.W4EmployerStreet
	}
	if req.BusinessCity == "" {
		req.BusinessCity = req.W4EmployerCity
	}
	if req.BusinessState == "" {
		req.BusinessState = req.W4EmployerState
	}
	if req.BusinessEIN == "" {
		req.BusinessEIN = req.W4EmployerEIN
	}
	if req.BusinessStreet == "" && req.BusinessCity == "" && req.BusinessState == "" {
		street, city, state := splitBusinessAddressParts(req.BusinessAddress)
		if street == "" && city == "" && state == "" {
			street, city, state = splitBusinessAddressParts(req.W4EmployerAddress)
		}
		req.BusinessStreet = street
		req.BusinessCity = city
		req.BusinessState = state
	}
	req.BusinessAddress = composeBusinessAddress(req.BusinessStreet, req.BusinessCity, req.BusinessState)
	if req.BusinessName == "" {
		writeError(w, http.StatusBadRequest, "business or organization name is required")
		return
	}
	if req.BusinessStreet == "" {
		writeError(w, http.StatusBadRequest, "business street is required")
		return
	}
	if req.BusinessCity == "" {
		writeError(w, http.StatusBadRequest, "business city is required")
		return
	}
	if req.BusinessState == "" {
		writeError(w, http.StatusBadRequest, "business state is required")
		return
	}
	if req.BusinessEIN == "" {
		writeError(w, http.StatusBadRequest, "business EIN is required")
		return
	}
	if len(req.BusinessName) > 160 {
		writeError(w, http.StatusBadRequest, "business or organization name must be 160 characters or fewer")
		return
	}
	if len(req.BusinessStreet) > 180 {
		writeError(w, http.StatusBadRequest, "business street must be 180 characters or fewer")
		return
	}
	if len(req.BusinessCity) > 100 {
		writeError(w, http.StatusBadRequest, "business city must be 100 characters or fewer")
		return
	}
	if len(req.BusinessState) > 60 {
		writeError(w, http.StatusBadRequest, "business state must be 60 characters or fewer")
		return
	}
	if len(req.BusinessEIN) > 32 {
		writeError(w, http.StatusBadRequest, "business EIN must be 32 characters or fewer")
		return
	}
	if len(req.BusinessAddress) > 260 {
		writeError(w, http.StatusBadRequest, "business address must be 260 characters or fewer")
		return
	}
	if len(req.RestaurantUsername) > 120 {
		writeError(w, http.StatusBadRequest, "restaurant username must be 120 characters or fewer")
		return
	}
	if req.RestaurantPassword != "" && (len(req.RestaurantPassword) < 4 || len(req.RestaurantPassword) > 64) {
		writeError(w, http.StatusBadRequest, "restaurant password must be between 4 and 64 characters")
		return
	}
	departments := sanitizeDepartments(req.Departments)
	if len(req.Departments) == 0 && currentSettings != nil {
		departments = sanitizeDepartments(currentSettings.Departments)
	}
	if err := withSQLiteRetry(func() error {
		return s.store.upsertLocationSettings(r.Context(), locationSettings{
			LocationNumber:       number,
			EmployerRepSignature: req.EmployerRepSignature,
			BusinessName:         req.BusinessName,
			BusinessStreet:       req.BusinessStreet,
			BusinessCity:         req.BusinessCity,
			BusinessState:        req.BusinessState,
			BusinessEIN:          req.BusinessEIN,
			BusinessAddress:      req.BusinessAddress,
			W4EmployerName:       req.BusinessName,
			W4EmployerStreet:     req.BusinessStreet,
			W4EmployerCity:       req.BusinessCity,
			W4EmployerState:      req.BusinessState,
			W4EmployerEIN:        req.BusinessEIN,
			W4EmployerAddress:    req.BusinessAddress,
			Departments:          departments,
			RestaurantUsername:   req.RestaurantUsername,
		})
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "unable to persist location settings")
		return
	}
	if req.RestaurantUsername == "" {
		if err := withSQLiteRetry(func() error {
			return s.store.deleteRestaurantUsersForLocation(r.Context(), number)
		}); err != nil {
			writeError(w, http.StatusInternalServerError, "settings saved but unable to disable restaurant login")
			return
		}
	} else if req.RestaurantPassword != "" {
		if err := withSQLiteRetry(func() error {
			return s.store.upsertRestaurantUser(r.Context(), number, req.RestaurantUsername, req.RestaurantPassword)
		}); err != nil {
			writeError(w, http.StatusInternalServerError, "settings saved but unable to configure restaurant login")
			return
		}
	} else {
		exists, err := s.store.restaurantUserExists(r.Context(), number, req.RestaurantUsername)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "unable to validate restaurant login")
			return
		}
		if !exists {
			writeError(w, http.StatusBadRequest, "restaurant password is required when setting a new restaurant username")
			return
		}
		if err := withSQLiteRetry(func() error {
			return s.store.deleteOtherRestaurantUsersForLocation(r.Context(), number, req.RestaurantUsername)
		}); err != nil {
			writeError(w, http.StatusInternalServerError, "settings saved but unable to update restaurant login")
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "settings saved"})
}

func (s *server) listLocationCandidateValues(w http.ResponseWriter, r *http.Request, number string) {
	if _, err := s.store.getLocationByNumber(r.Context(), number); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "location not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load location")
		return
	}
	values, err := s.store.listCandidateValues(r.Context(), number)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to load candidate values")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"count":  len(values),
		"values": values,
	})
}

func (s *server) createLocationCandidateValue(w http.ResponseWriter, r *http.Request, number string) {
	if _, err := s.store.getLocationByNumber(r.Context(), number); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "location not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load location")
		return
	}
	var req createCandidateValueRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	req.Description = strings.TrimSpace(req.Description)
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "value name is required")
		return
	}
	if len([]rune(req.Name)) > 80 {
		writeError(w, http.StatusBadRequest, "value name must be 80 characters or fewer")
		return
	}
	if len([]rune(req.Description)) > 400 {
		writeError(w, http.StatusBadRequest, "value description must be 400 characters or fewer")
		return
	}
	value := candidateValue{
		LocationNumber: number,
		Name:           req.Name,
		Description:    req.Description,
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
	}
	id, err := s.store.createCandidateValue(r.Context(), value)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			writeError(w, http.StatusConflict, "a candidate value with this name already exists")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to create candidate value")
		return
	}
	value.ID = id
	writeJSON(w, http.StatusCreated, map[string]any{
		"message": "candidate value created",
		"value":   value,
	})
}

func (s *server) updateLocationCandidateValue(w http.ResponseWriter, r *http.Request, number string, valueID int64) {
	var req updateCandidateValueRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	req.Description = strings.TrimSpace(req.Description)
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "value name is required")
		return
	}
	if len([]rune(req.Name)) > 80 {
		writeError(w, http.StatusBadRequest, "value name must be 80 characters or fewer")
		return
	}
	if len([]rune(req.Description)) > 400 {
		writeError(w, http.StatusBadRequest, "value description must be 400 characters or fewer")
		return
	}
	if err := s.store.updateCandidateValue(r.Context(), number, valueID, req.Name, req.Description); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "candidate value not found")
			return
		}
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			writeError(w, http.StatusConflict, "a candidate value with this name already exists")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to update candidate value")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "candidate value updated"})
}

func (s *server) deleteLocationCandidateValue(w http.ResponseWriter, r *http.Request, number string, valueID int64) {
	if err := s.store.deleteCandidateValue(r.Context(), number, valueID); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "candidate value not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to delete candidate value")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "candidate value deleted"})
}

func (s *server) listLocationCandidateInterviewNames(w http.ResponseWriter, r *http.Request, number string) {
	if _, err := s.store.getLocationByNumber(r.Context(), number); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "location not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load location")
		return
	}
	names, err := s.store.listCandidateInterviewNames(r.Context(), number)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to load interview types")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"count": len(names),
		"names": names,
	})
}

func (s *server) createLocationCandidateInterviewName(w http.ResponseWriter, r *http.Request, number string) {
	if _, err := s.store.getLocationByNumber(r.Context(), number); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "location not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load location")
		return
	}
	var req createCandidateInterviewNameRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "interview type is required")
		return
	}
	if len([]rune(req.Name)) > 80 {
		writeError(w, http.StatusBadRequest, "interview type must be 80 characters or fewer")
		return
	}
	record := candidateInterviewName{
		LocationNumber: number,
		Name:           req.Name,
		Priority:       100,
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
	}
	if req.Priority != nil {
		if *req.Priority < 0 || *req.Priority > 10000 {
			writeError(w, http.StatusBadRequest, "priority must be between 0 and 10000")
			return
		}
		record.Priority = *req.Priority
	}
	id, err := s.store.createCandidateInterviewName(r.Context(), record)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			writeError(w, http.StatusConflict, "an interview type with this value already exists")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to create interview type")
		return
	}
	record.ID = id
	writeJSON(w, http.StatusCreated, map[string]any{
		"message": "interview type created",
		"name":    record,
	})
}

func (s *server) deleteLocationCandidateInterviewName(w http.ResponseWriter, r *http.Request, number string, nameID int64) {
	if err := s.store.deleteCandidateInterviewName(r.Context(), number, nameID); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "interview type not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to delete interview type")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "interview type deleted"})
}

func (s *server) updateLocationCandidateInterviewName(w http.ResponseWriter, r *http.Request, number string, nameID int64) {
	if _, err := s.store.getLocationByNumber(r.Context(), number); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "location not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load location")
		return
	}
	var req updateCandidateInterviewNameRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Priority == nil {
		writeError(w, http.StatusBadRequest, "priority is required")
		return
	}
	priority := *req.Priority
	if priority < 0 || priority > 10000 {
		writeError(w, http.StatusBadRequest, "priority must be between 0 and 10000")
		return
	}
	if err := s.store.updateCandidateInterviewNamePriority(r.Context(), number, nameID, priority); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "interview type not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to update interview type")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "interview type updated"})
}

func (s *server) listLocationCandidateInterviewQuestions(w http.ResponseWriter, r *http.Request, number string) {
	if _, err := s.store.getLocationByNumber(r.Context(), number); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "location not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load location")
		return
	}
	questions, err := s.store.listCandidateInterviewQuestions(r.Context(), number, 0)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to load interview questions")
		return
	}
	writeJSON(w, http.StatusOK, candidateInterviewQuestionsResponse{
		Count:     len(questions),
		Questions: questions,
	})
}

func (s *server) createLocationCandidateInterviewQuestion(w http.ResponseWriter, r *http.Request, number string) {
	if _, err := s.store.getLocationByNumber(r.Context(), number); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "location not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load location")
		return
	}
	var req createCandidateInterviewQuestionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.Question = strings.TrimSpace(req.Question)
	if req.Question == "" {
		writeError(w, http.StatusBadRequest, "question is required")
		return
	}
	if len([]rune(req.Question)) > 500 {
		writeError(w, http.StatusBadRequest, "question must be 500 characters or fewer")
		return
	}
	if hasDuplicateQuestionResponseOptions(req.ResponseOptions) {
		writeError(w, http.StatusBadRequest, "multiple choice options must be unique")
		return
	}
	responseType := normalizeQuestionResponseType(req.ResponseType)
	responseOptions := normalizeQuestionResponseOptions(req.ResponseOptions)
	if err := validateCandidateInterviewQuestionDefinition(responseType, responseOptions); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	interviewNameIDs := normalizeInterviewNameIDs(req.InterviewNameIDs, req.InterviewNameID)
	interviewNamesByID := map[int64]string{}
	if len(interviewNameIDs) > 0 {
		names, err := s.store.listCandidateInterviewNames(r.Context(), number)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "unable to load interview types")
			return
		}
		for _, name := range names {
			interviewNamesByID[name.ID] = name.Name
		}
		for _, nameID := range interviewNameIDs {
			if _, ok := interviewNamesByID[nameID]; !ok {
				writeError(w, http.StatusBadRequest, "select valid interview types for this location")
				return
			}
		}
	}
	record := candidateInterviewQuestion{
		LocationNumber:  number,
		Question:        req.Question,
		ResponseType:    responseType,
		ResponseOptions: append([]string{}, responseOptions...),
		CreatedAt:       time.Now().UTC(),
		UpdatedAt:       time.Now().UTC(),
	}
	id, err := s.store.createCandidateInterviewQuestion(r.Context(), record)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to create interview question")
		return
	}
	if err := s.store.updateCandidateInterviewQuestion(r.Context(), number, id, interviewNameIDs, nil, &responseType, &responseOptions); err != nil {
		_ = s.store.deleteCandidateInterviewQuestion(r.Context(), number, id)
		writeError(w, http.StatusInternalServerError, "unable to assign interview types")
		return
	}
	record.ID = id
	record.InterviewNameIDs = append(record.InterviewNameIDs, interviewNameIDs...)
	for _, nameID := range interviewNameIDs {
		record.InterviewNames = append(record.InterviewNames, interviewNamesByID[nameID])
	}
	if len(record.InterviewNameIDs) > 0 {
		record.InterviewNameID = record.InterviewNameIDs[0]
		record.InterviewName = record.InterviewNames[0]
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"message":  "interview question created",
		"question": record,
	})
}

func (s *server) updateLocationCandidateInterviewQuestion(w http.ResponseWriter, r *http.Request, number string, questionID int64) {
	if _, err := s.store.getLocationByNumber(r.Context(), number); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "location not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load location")
		return
	}
	var req updateCandidateInterviewQuestionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	interviewNameIDs := normalizeInterviewNameIDs(req.InterviewNameIDs, req.InterviewNameID)
	if len(interviewNameIDs) > 0 {
		names, err := s.store.listCandidateInterviewNames(r.Context(), number)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "unable to load interview types")
			return
		}
		allowed := make(map[int64]struct{}, len(names))
		for _, name := range names {
			allowed[name.ID] = struct{}{}
		}
		for _, nameID := range interviewNameIDs {
			if _, ok := allowed[nameID]; !ok {
				writeError(w, http.StatusBadRequest, "select valid interview types for this location")
				return
			}
		}
	}
	var questionUpdate *string
	if req.Question != nil {
		trimmed := strings.TrimSpace(*req.Question)
		if trimmed == "" {
			writeError(w, http.StatusBadRequest, "question is required")
			return
		}
		if len([]rune(trimmed)) > 500 {
			writeError(w, http.StatusBadRequest, "question must be 500 characters or fewer")
			return
		}
		questionUpdate = &trimmed
	}
	var responseTypeUpdate *string
	var responseOptionsUpdate *[]string
	if req.ResponseType != nil {
		normalized := normalizeQuestionResponseType(*req.ResponseType)
		responseTypeUpdate = &normalized
		if hasDuplicateQuestionResponseOptions(req.ResponseOptions) {
			writeError(w, http.StatusBadRequest, "multiple choice options must be unique")
			return
		}
		normalizedOptions := normalizeQuestionResponseOptions(req.ResponseOptions)
		responseOptionsUpdate = &normalizedOptions
		if err := validateCandidateInterviewQuestionDefinition(normalized, normalizedOptions); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	} else if len(req.ResponseOptions) > 0 {
		writeError(w, http.StatusBadRequest, "response type is required when setting response options")
		return
	}
	if err := s.store.updateCandidateInterviewQuestion(r.Context(), number, questionID, interviewNameIDs, questionUpdate, responseTypeUpdate, responseOptionsUpdate); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "interview question not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to update interview question")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "interview question updated"})
}

func (s *server) deleteLocationCandidateInterviewQuestion(w http.ResponseWriter, r *http.Request, number string, questionID int64) {
	if err := s.store.deleteCandidateInterviewQuestion(r.Context(), number, questionID); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "interview question not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to delete interview question")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "interview question deleted"})
}

func (s *server) listLocationCandidates(w http.ResponseWriter, r *http.Request, number string) {
	if _, err := s.store.getLocationByNumber(r.Context(), number); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "location not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load location")
		return
	}
	archived := parseBoolQueryValue(r.URL.Query().Get("archived"))
	search := strings.TrimSpace(r.URL.Query().Get("search"))
	candidates, err := s.store.listCandidates(r.Context(), number, archived, search)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to load candidates")
		return
	}
	for i := range candidates {
		interviews, err := s.store.listCandidateInterviews(r.Context(), number, candidates[i].ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "unable to load candidate interviews")
			return
		}
		candidates[i].Interviews = interviews
		candidates[i].AverageGradePercent = candidateAverageGradePercent(interviews)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"count":      len(candidates),
		"candidates": candidates,
	})
}

func (s *server) createLocationCandidate(w http.ResponseWriter, r *http.Request, number string) {
	if _, err := s.store.getLocationByNumber(r.Context(), number); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "location not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load location")
		return
	}
	var req createCandidateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.FirstName = strings.TrimSpace(req.FirstName)
	req.LastName = strings.TrimSpace(req.LastName)
	req.Phone = strings.TrimSpace(req.Phone)
	if req.FirstName == "" || req.LastName == "" || req.Phone == "" {
		writeError(w, http.StatusBadRequest, "first name, last name, and phone are required")
		return
	}
	if len([]rune(req.FirstName)) > 80 || len([]rune(req.LastName)) > 80 {
		writeError(w, http.StatusBadRequest, "first and last name must be 80 characters or fewer")
		return
	}
	if len([]rune(req.Phone)) > 40 {
		writeError(w, http.StatusBadRequest, "phone must be 40 characters or fewer")
		return
	}
	now := time.Now().UTC()
	candidateRecord := candidate{
		LocationNumber: number,
		FirstName:      req.FirstName,
		LastName:       req.LastName,
		Phone:          req.Phone,
		Status:         "active",
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	id, err := s.store.createCandidate(r.Context(), candidateRecord)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to create candidate")
		return
	}
	candidateRecord.ID = id
	writeJSON(w, http.StatusCreated, map[string]any{
		"message":   "candidate created",
		"candidate": candidateRecord,
	})
}

func (s *server) deleteLocationCandidate(w http.ResponseWriter, r *http.Request, number string, candidateID int64) {
	if err := s.store.deleteCandidate(r.Context(), number, candidateID); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "candidate not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to delete candidate")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "candidate deleted"})
}

func (s *server) getLocationCandidate(w http.ResponseWriter, r *http.Request, number string, candidateID int64) {
	c, err := s.store.getCandidateByID(r.Context(), number, candidateID)
	if err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "candidate not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load candidate")
		return
	}
	interviews, err := s.store.listCandidateInterviews(r.Context(), number, candidateID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to load interviews")
		return
	}
	c.Interviews = interviews
	c.AverageGradePercent = candidateAverageGradePercent(interviews)
	writeJSON(w, http.StatusOK, map[string]any{"candidate": c})
}

func (s *server) getLocationCandidateScorecard(w http.ResponseWriter, r *http.Request, number string, candidateID int64) {
	s.getLocationCandidate(w, r, number, candidateID)
}

func (s *server) listEmployeeCandidateScorecards(w http.ResponseWriter, r *http.Request, number, timePunchName string) {
	if _, err := s.store.getLocationByNumber(r.Context(), number); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "location not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load location")
		return
	}
	scorecards, err := s.store.listHiredCandidateScorecardsByTimePunchName(r.Context(), number, timePunchName)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to load scorecards")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"count":      len(scorecards),
		"candidates": scorecards,
	})
}

func (s *server) createLocationCandidateInterview(w http.ResponseWriter, r *http.Request, number string, candidateID int64) {
	candidateRecord, err := s.store.getCandidateByID(r.Context(), number, candidateID)
	if err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "candidate not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load candidate")
		return
	}
	if candidateRecord.Status != "active" {
		writeError(w, http.StatusBadRequest, "interviews are allowed only for active candidates")
		return
	}
	var req createCandidateInterviewRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.InterviewerTimePunchName = strings.TrimSpace(req.InterviewerTimePunchName)
	req.Notes = strings.TrimSpace(req.Notes)
	if req.InterviewerTimePunchName == "" {
		writeError(w, http.StatusBadRequest, "interviewer is required")
		return
	}
	resolvedInterviewer, interviewerErr := s.resolveInterviewInterviewer(r.Context(), number, req.InterviewerTimePunchName)
	if interviewerErr != nil {
		msg := interviewerErr.Error()
		if msg == "interviewer is required" ||
			msg == "interviewer must be an active employee in this location" ||
			msg == "interviewer must be owner/operator until first employee is hired" {
			writeError(w, http.StatusBadRequest, msg)
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to validate interviewer")
		return
	}
	req.InterviewerTimePunchName = resolvedInterviewer
	interviewName, err := s.resolveInterviewNameForLocation(r.Context(), number, req.InterviewType)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to load interview types")
		return
	}
	if interviewName == "" {
		writeError(w, http.StatusBadRequest, "select a valid interview type for this location")
		return
	}
	interviewNameID, err := s.resolveInterviewNameIDForLocation(r.Context(), number, interviewName)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to load interview types")
		return
	}
	questions, err := s.store.listCandidateInterviewQuestions(r.Context(), number, interviewNameID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to load interview questions")
		return
	}
	if len(questions) == 0 {
		writeError(w, http.StatusBadRequest, "create at least one interview question for this interview type before interviewing")
		return
	}
	values, err := s.store.listCandidateValues(r.Context(), number)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to load candidate values")
		return
	}
	if len(values) == 0 {
		writeError(w, http.StatusBadRequest, "create at least one candidate value before interviewing")
		return
	}
	gradesByValueID := make(map[int64]string, len(req.Grades))
	commentsByValueID := make(map[int64]string, len(req.GradeComments))
	for rawValueID, rawGrade := range req.Grades {
		valueID, parseErr := strconv.ParseInt(strings.TrimSpace(rawValueID), 10, 64)
		if parseErr != nil || valueID <= 0 {
			continue
		}
		grade := normalizeLetterGrade(rawGrade)
		if grade != "" {
			gradesByValueID[valueID] = grade
		}
	}
	for rawValueID, rawComment := range req.GradeComments {
		valueID, parseErr := strconv.ParseInt(strings.TrimSpace(rawValueID), 10, 64)
		if parseErr != nil || valueID <= 0 {
			continue
		}
		comment := strings.TrimSpace(rawComment)
		if len([]rune(comment)) > 1000 {
			writeError(w, http.StatusBadRequest, "value comments must be 1000 characters or fewer")
			return
		}
		commentsByValueID[valueID] = comment
	}
	interviewGrades := make([]candidateInterviewGrade, 0, len(values))
	for _, value := range values {
		grade := normalizeLetterGrade(gradesByValueID[value.ID])
		if grade == "" {
			writeError(w, http.StatusBadRequest, "every candidate value must be graded with A, B, C, D, or F")
			return
		}
		comment := strings.TrimSpace(commentsByValueID[value.ID])
		if comment == "" {
			writeError(w, http.StatusBadRequest, "every candidate value must include a comment")
			return
		}
		interviewGrades = append(interviewGrades, candidateInterviewGrade{
			ValueID:     value.ID,
			ValueName:   value.Name,
			LetterGrade: grade,
			Comment:     comment,
			Score:       letterGradeScore(grade),
		})
	}
	questionAnswersByID := make(map[int64]string, len(req.QuestionAnswers))
	for rawQuestionID, rawAnswer := range req.QuestionAnswers {
		questionID, parseErr := strconv.ParseInt(strings.TrimSpace(rawQuestionID), 10, 64)
		if parseErr != nil || questionID <= 0 {
			continue
		}
		answer := strings.TrimSpace(rawAnswer)
		if len([]rune(answer)) > 3000 {
			writeError(w, http.StatusBadRequest, "interview question answers must be 3000 characters or fewer")
			return
		}
		questionAnswersByID[questionID] = answer
	}
	questionAnswers := make([]candidateInterviewQuestionAnswer, 0, len(questions))
	for _, question := range questions {
		answer := strings.TrimSpace(questionAnswersByID[question.ID])
		if err := validateCandidateInterviewQuestionAnswer(question, answer); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		questionAnswers = append(questionAnswers, candidateInterviewQuestionAnswer{
			QuestionID:   question.ID,
			QuestionText: question.Question,
			Answer:       answer,
		})
	}
	now := time.Now().UTC()
	interview := candidateInterview{
		CandidateID:              candidateID,
		LocationNumber:           number,
		InterviewerTimePunchName: req.InterviewerTimePunchName,
		InterviewType:            interviewName,
		Notes:                    req.Notes,
		CreatedAt:                now,
		Grades:                   interviewGrades,
		QuestionAnswers:          questionAnswers,
	}
	id, err := s.store.createCandidateInterview(r.Context(), interview)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to create interview")
		return
	}
	interview.ID = id
	writeJSON(w, http.StatusCreated, map[string]any{
		"message":   "interview submitted",
		"interview": interview,
	})
}

func (s *server) createLocationCandidateInterviewLink(w http.ResponseWriter, r *http.Request, number string, candidateID int64) {
	candidateRecord, err := s.store.getCandidateByID(r.Context(), number, candidateID)
	if err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "candidate not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load candidate")
		return
	}
	if candidateRecord.Status != "active" {
		writeError(w, http.StatusBadRequest, "interviews are allowed only for active candidates")
		return
	}
	var req createCandidateInterviewLinkRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.InterviewerTimePunchName = strings.TrimSpace(req.InterviewerTimePunchName)
	if req.InterviewerTimePunchName == "" {
		writeError(w, http.StatusBadRequest, "interviewer is required")
		return
	}
	scheduledAt, err := parseInterviewScheduledAt(req.ScheduledAt)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	resolvedInterviewer, interviewerErr := s.resolveInterviewInterviewer(r.Context(), number, req.InterviewerTimePunchName)
	if interviewerErr != nil {
		msg := interviewerErr.Error()
		if msg == "interviewer is required" ||
			msg == "interviewer must be an active employee in this location" ||
			msg == "interviewer must be owner/operator until first employee is hired" {
			writeError(w, http.StatusBadRequest, msg)
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to validate interviewer")
		return
	}
	req.InterviewerTimePunchName = resolvedInterviewer
	interviewName, err := s.resolveInterviewNameForLocation(r.Context(), number, req.InterviewType)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to load interview types")
		return
	}
	if interviewName == "" {
		writeError(w, http.StatusBadRequest, "select a valid interview type for this location")
		return
	}
	interviewNameID, err := s.resolveInterviewNameIDForLocation(r.Context(), number, interviewName)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to load interview types")
		return
	}
	questions, err := s.store.listCandidateInterviewQuestions(r.Context(), number, interviewNameID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to load interview questions")
		return
	}
	if len(questions) == 0 {
		writeError(w, http.StatusBadRequest, "create at least one interview question for this interview type before generating links")
		return
	}
	token, err := randomToken(32)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to generate interview link")
		return
	}
	neverExpiresAt := time.Date(9999, time.December, 31, 23, 59, 59, 0, time.UTC)
	if err := s.store.createCandidateInterviewToken(r.Context(), candidateInterviewToken{
		Token:                    token,
		LocationNumber:           number,
		CandidateID:              candidateID,
		InterviewerTimePunchName: req.InterviewerTimePunchName,
		InterviewType:            interviewName,
		ScheduledAt:              scheduledAt,
		ExpiresAt:                neverExpiresAt,
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "unable to create interview link")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"token":       token,
		"link":        "/interview/" + token,
		"scheduledAt": scheduledAt,
	})
}

func (s *server) listLocationCandidateInterviewLinks(w http.ResponseWriter, r *http.Request, number string, candidateID int64) {
	if _, err := s.store.getCandidateByID(r.Context(), number, candidateID); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "candidate not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load candidate")
		return
	}
	links, err := s.store.listCandidateInterviewLinks(r.Context(), number, candidateID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to load interview links")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"count": len(links),
		"links": links,
	})
}

func (s *server) listLocationInterviewCalendar(w http.ResponseWriter, r *http.Request, number string) {
	if _, err := s.store.getLocationByNumber(r.Context(), number); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "location not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load location")
		return
	}
	entries, err := s.store.listLocationInterviewCalendar(r.Context(), number)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to load interview calendar")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"count":    len(entries),
		"calendar": entries,
	})
}

func (s *server) getLocationCandidateInterviewLink(w http.ResponseWriter, r *http.Request, number string, candidateID int64, token string) {
	if _, err := s.store.getCandidateByID(r.Context(), number, candidateID); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "candidate not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load candidate")
		return
	}
	link, err := s.store.getCandidateInterviewLink(r.Context(), number, candidateID, token)
	if err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "interview link not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load interview link")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"link": link})
}

func (s *server) deleteLocationCandidateInterviewLink(w http.ResponseWriter, r *http.Request, number string, candidateID int64, token string) {
	if _, err := s.store.getCandidateByID(r.Context(), number, candidateID); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "candidate not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load candidate")
		return
	}
	link, err := s.store.getCandidateInterviewLink(r.Context(), number, candidateID, token)
	if err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "interview link not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load interview link")
		return
	}
	if link.UsedAt != nil {
		writeError(w, http.StatusBadRequest, "completed interviews cannot be deleted")
		return
	}
	if err := s.store.deleteCandidateInterviewLink(r.Context(), number, candidateID, token); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "interview link not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to delete interview link")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "interview link deleted"})
}

func (s *server) updateLocationCandidateDecision(w http.ResponseWriter, r *http.Request, number string, candidateID int64) {
	candidateRecord, err := s.store.getCandidateByID(r.Context(), number, candidateID)
	if err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "candidate not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load candidate")
		return
	}
	if candidateRecord.Status != "active" {
		writeError(w, http.StatusBadRequest, "candidate has already been decided")
		return
	}
	var req updateCandidateDecisionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	decision := strings.ToLower(strings.TrimSpace(req.Decision))
	switch decision {
	case "pass":
		if err := s.store.updateCandidateStatus(r.Context(), number, candidateID, "passed", ""); err != nil {
			writeError(w, http.StatusInternalServerError, "unable to update candidate decision")
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"message": "candidate passed and archived"})
		return
	case "hire":
		if req.DepartmentID <= 0 {
			writeError(w, http.StatusBadRequest, "department is required when hiring")
			return
		}
		payBandID := req.PayBandID
		if payBandID <= 0 {
			payBandID = req.JobID
		}
		if payBandID <= 0 {
			writeError(w, http.StatusBadRequest, "pay band is required when hiring")
			return
		}
		firstName := strings.TrimSpace(req.FirstName)
		if firstName == "" {
			firstName = strings.TrimSpace(candidateRecord.FirstName)
		}
		lastName := strings.TrimSpace(req.LastName)
		if lastName == "" {
			lastName = strings.TrimSpace(candidateRecord.LastName)
		}
		if firstName == "" || lastName == "" {
			writeError(w, http.StatusBadRequest, "first name and last name are required when hiring")
			return
		}
		birthday := ""
		if parsedBirthday, ok := normalizeBirthday(strings.TrimSpace(req.Birthday)); ok {
			birthday = parsedBirthday
		}
		email := strings.TrimSpace(req.Email)
		phone := strings.TrimSpace(req.Phone)
		if phone == "" {
			phone = strings.TrimSpace(candidateRecord.Phone)
		}
		address := strings.TrimSpace(req.Address)
		aptNumber := strings.TrimSpace(req.AptNumber)
		city := strings.TrimSpace(req.City)
		state := ""
		if normalized := normalizeUSStateCode(req.State); normalized != "" {
			state = normalized
		}
		zipCode := strings.TrimSpace(req.ZipCode)
		job, err := s.store.getLocationJobByID(r.Context(), number, payBandID)
		if err != nil {
			if errors.Is(err, errNotFound) {
				writeError(w, http.StatusBadRequest, "invalid pay band")
				return
			}
			writeError(w, http.StatusInternalServerError, "unable to load pay band")
			return
		}
		payType := strings.ToLower(strings.TrimSpace(job.PayType))
		if payType != "hourly" && payType != "salary" {
			writeError(w, http.StatusBadRequest, "selected pay band has an invalid pay type")
			return
		}
		payAmountCents := job.PayAmountCents
		if payAmountCents <= 0 {
			writeError(w, http.StatusBadRequest, "selected pay band has an invalid pay amount")
			return
		}
		departments, err := s.store.listLocationDepartments(r.Context(), number)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "unable to load departments")
			return
		}
		departmentName := departmentNameByID(departments, req.DepartmentID)
		if departmentName == "" {
			writeError(w, http.StatusBadRequest, "invalid department")
			return
		}
		if canonicalTimePunchName(firstName, lastName) == "" {
			writeError(w, http.StatusBadRequest, "unable to build employee time punch name")
			return
		}
		timePunchName, err := s.uniqueTimePunchNameForLocation(r.Context(), number, firstName, lastName)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "unable to generate employee time punch name")
			return
		}
		employeeRecord := employee{
			TimePunchName:  timePunchName,
			FirstName:      firstName,
			LastName:       lastName,
			Birthday:       birthday,
			Email:          email,
			Phone:          phone,
			Address:        address,
			AptNumber:      aptNumber,
			City:           city,
			State:          state,
			ZipCode:        zipCode,
			Department:     departmentName,
			DepartmentID:   req.DepartmentID,
			JobID:          job.ID,
			JobName:        job.Name,
			PayBandID:      job.ID,
			PayBandName:    job.Name,
			PayType:        payType,
			PayAmountCents: payAmountCents,
		}
		if err := s.store.upsertLocationEmployee(r.Context(), number, employeeRecord); err != nil {
			writeError(w, http.StatusInternalServerError, "unable to create employee from candidate")
			return
		}
		if err := s.store.updateCandidateStatus(r.Context(), number, candidateID, "hired", timePunchName); err != nil {
			writeError(w, http.StatusInternalServerError, "employee created but unable to finalize candidate hire status")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"message":       "candidate hired",
			"timePunchName": timePunchName,
		})
		return
	default:
		writeError(w, http.StatusBadRequest, "decision must be hire or pass")
		return
	}
}

func (s *server) listLocationTimePunchEntries(w http.ResponseWriter, r *http.Request, number string) {
	if _, err := s.store.getLocationByNumber(r.Context(), number); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "location not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load location")
		return
	}
	includeArchived := parseBoolQueryValue(r.URL.Query().Get("archived"))
	entries, err := s.store.listTimePunchEntries(r.Context(), number, includeArchived)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to load time punch entries")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"count":   len(entries),
		"entries": entries,
	})
}

func (s *server) createLocationTimePunchEntry(w http.ResponseWriter, r *http.Request, number string) {
	if _, err := s.store.getLocationByNumber(r.Context(), number); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "location not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load location")
		return
	}
	var req createTimePunchEntryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.TimePunchName = strings.TrimSpace(req.TimePunchName)
	req.PunchDate = strings.TrimSpace(req.PunchDate)
	req.TimeIn = strings.TrimSpace(req.TimeIn)
	req.TimeOut = strings.TrimSpace(req.TimeOut)
	req.Note = strings.TrimSpace(req.Note)
	if err := validateCreateTimePunchEntry(req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, err := s.store.getLocationEmployee(r.Context(), number, req.TimePunchName); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusBadRequest, "employee is not active in this location")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load employee")
		return
	}
	err := withSQLiteRetry(func() error {
		return s.store.createTimePunchEntry(r.Context(), timePunchEntry{
			LocationNum:              number,
			TimePunchName:            req.TimePunchName,
			PunchDate:                req.PunchDate,
			TimeIn:                   req.TimeIn,
			TimeOut:                  req.TimeOut,
			Note:                     req.Note,
			ForgotBreakClockInReturn: req.ForgotBreakClockInReturn,
			CreatedAt:                time.Now().UTC(),
		})
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to save time punch entry")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"message": "time punch correction submitted"})
}

func (s *server) listLocationBusinessDays(w http.ResponseWriter, r *http.Request, number string) {
	if _, err := s.store.getLocationByNumber(r.Context(), number); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "location not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load location")
		return
	}
	days, err := s.store.listBusinessDays(r.Context(), number)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to load business days")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"count":        len(days),
		"businessDays": days,
	})
}

func (s *server) createLocationBusinessDay(w http.ResponseWriter, r *http.Request, number string) {
	if _, err := s.store.getLocationByNumber(r.Context(), number); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "location not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load location")
		return
	}
	var req createBusinessDayRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.BusinessDate = strings.TrimSpace(req.BusinessDate)
	req.StartDate = strings.TrimSpace(req.StartDate)
	req.EndDate = strings.TrimSpace(req.EndDate)

	dates, err := resolveBusinessDayDatesForCreate(req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	existing, err := s.store.findExistingBusinessDates(r.Context(), number, dates)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to validate business day range")
		return
	}
	if len(existing) > 0 {
		writeError(w, http.StatusBadRequest, "one or more business days already exist in this range")
		return
	}

	now := time.Now().UTC()
	err = withSQLiteRetry(func() error {
		return s.store.insertBusinessDays(r.Context(), number, dates, now)
	})
	if err != nil {
		lower := strings.ToLower(err.Error())
		if strings.Contains(lower, "unique constraint failed") {
			writeError(w, http.StatusBadRequest, "one or more business days already exist in this range")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to persist business day")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"message": "business days created",
		"count":   len(dates),
	})
}

func (s *server) getOrCreateLocationBusinessDay(w http.ResponseWriter, r *http.Request, number, businessDate string) {
	if _, err := s.store.getLocationByNumber(r.Context(), number); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "location not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load location")
		return
	}
	day, err := s.store.getOrCreateBusinessDay(r.Context(), number, businessDate)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to load business day")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"businessDay": day})
}

func (s *server) updateLocationBusinessDay(w http.ResponseWriter, r *http.Request, number, businessDate string) {
	if _, err := s.store.getLocationByNumber(r.Context(), number); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "location not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load location")
		return
	}
	var req updateBusinessDayRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.TotalSales = strings.TrimSpace(req.TotalSales)
	req.LaborHours = strings.TrimSpace(req.LaborHours)
	totalSales, laborHours, err := validateUpdateBusinessDay(req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	err = withSQLiteRetry(func() error {
		return s.store.updateBusinessDayMetricsByDate(r.Context(), number, businessDate, totalSales, laborHours)
	})
	if err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "business day not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to update business day")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "business day updated"})
}

func (s *server) getLocationTimePunchLink(w http.ResponseWriter, r *http.Request, number string) {
	if _, err := s.store.getLocationByNumber(r.Context(), number); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "location not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load location")
		return
	}
	token, err := s.store.getOrCreateLocationTimePunchToken(r.Context(), number)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to create time punch link")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"token": token})
}

func (s *server) getLocationTimeOffLink(w http.ResponseWriter, r *http.Request, number string) {
	if _, err := s.store.getLocationByNumber(r.Context(), number); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "location not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load location")
		return
	}
	token, err := s.store.getOrCreateLocationTimeOffToken(r.Context(), number)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to create time off link")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"token": token})
}

func (s *server) listLocationTimeOffRequests(w http.ResponseWriter, r *http.Request, number string) {
	if _, err := s.store.getLocationByNumber(r.Context(), number); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "location not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load location")
		return
	}
	includeArchived := parseBoolQueryValue(r.URL.Query().Get("archived"))
	requests, err := s.store.listTimeOffRequests(r.Context(), number, includeArchived)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to load time off requests")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"count":    len(requests),
		"requests": requests,
	})
}

func (s *server) createLocationTimeOffRequest(w http.ResponseWriter, r *http.Request, number string) {
	if _, err := s.store.getLocationByNumber(r.Context(), number); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "location not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load location")
		return
	}
	var req createTimeOffRequestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	startDate, endDate, err := validateCreateTimeOffRequest(req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, err := s.store.getLocationEmployee(r.Context(), number, strings.TrimSpace(req.TimePunchName)); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusBadRequest, "employee not found for this location")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to validate employee")
		return
	}
	err = withSQLiteRetry(func() error {
		return s.store.createTimeOffRequest(r.Context(), timeOffRequest{
			LocationNum:   number,
			TimePunchName: strings.TrimSpace(req.TimePunchName),
			StartDate:     startDate,
			EndDate:       endDate,
			CreatedAt:     time.Now().UTC(),
		})
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to save time off request")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "time off request submitted"})
}

func (s *server) archiveLocationTimeOffRequest(w http.ResponseWriter, r *http.Request, number string, requestID int64) {
	if _, err := s.store.getLocationByNumber(r.Context(), number); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "location not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load location")
		return
	}
	if err := withSQLiteRetry(func() error {
		return s.store.archiveTimeOffRequest(r.Context(), number, requestID)
	}); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "time off request not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to process time off request")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "time off request processed"})
}

func (s *server) deleteLocationTimePunchEntry(w http.ResponseWriter, r *http.Request, number string, entryID int64) {
	if _, err := s.store.getLocationByNumber(r.Context(), number); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "location not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load location")
		return
	}
	if err := s.store.deleteTimePunchEntry(r.Context(), number, entryID); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "time punch entry not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to delete time punch entry")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "time punch entry deleted"})
}

func (s *server) archiveLocationTimePunchEntry(w http.ResponseWriter, r *http.Request, number string, entryID int64) {
	if _, err := s.store.getLocationByNumber(r.Context(), number); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "location not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load location")
		return
	}
	if err := withSQLiteRetry(func() error {
		return s.store.archiveTimePunchEntry(r.Context(), number, entryID)
	}); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "time punch entry not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to complete time punch entry")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "time punch entry completed"})
}

func (s *server) getLocationEmployee(w http.ResponseWriter, r *http.Request, number, timePunchName string) {
	if _, err := s.store.getLocationByNumber(r.Context(), number); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "location not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load location")
		return
	}
	emp, err := s.store.getLocationEmployee(r.Context(), number, timePunchName)
	if err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "employee not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load employee")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"employee": emp})
}

func (s *server) terminateLocationEmployee(w http.ResponseWriter, r *http.Request, number, timePunchName string) {
	if _, err := s.store.getLocationByNumber(r.Context(), number); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "location not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load location")
		return
	}
	if _, err := s.store.getLocationEmployee(r.Context(), number, timePunchName); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "employee not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load employee")
		return
	}
	if err := withSQLiteRetry(func() error {
		return s.store.archiveAndDeleteLocationEmployee(r.Context(), number, timePunchName)
	}); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "employee not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to terminate employee")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "employee terminated"})
}

func (s *server) listArchivedLocationEmployees(w http.ResponseWriter, r *http.Request, number string) {
	if _, err := s.store.getLocationByNumber(r.Context(), number); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "location not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load location")
		return
	}
	employees, err := s.store.listArchivedLocationEmployees(r.Context(), number)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to load archived employees")
		return
	}
	sort.Slice(employees, func(i, j int) bool {
		if employees[i].LastName == employees[j].LastName {
			return employees[i].FirstName < employees[j].FirstName
		}
		return employees[i].LastName < employees[j].LastName
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"count":     len(employees),
		"employees": employees,
	})
}

func (s *server) getArchivedLocationEmployee(w http.ResponseWriter, r *http.Request, number, timePunchName string) {
	if _, err := s.store.getLocationByNumber(r.Context(), number); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "location not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load location")
		return
	}
	emp, err := s.store.getArchivedLocationEmployee(r.Context(), number, timePunchName)
	if err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "archived employee not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load archived employee")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"employee": emp})
}

func (s *server) getEmployeeI9(w http.ResponseWriter, r *http.Request, number, timePunchName string) {
	if _, err := s.store.getLocationEmployee(r.Context(), number, timePunchName); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "employee not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load employee")
		return
	}
	form, err := s.store.getEmployeeI9Form(r.Context(), number, timePunchName)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to load i9 form")
		return
	}
	docs, err := s.store.listEmployeeI9Documents(r.Context(), number, timePunchName)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to load i9 documents")
		return
	}
	history, err := s.store.listEmployeeI9FormHistory(r.Context(), number, timePunchName)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to load i9 history")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"i9":        form,
		"paperwork": form,
		"documents": docs,
		"history":   history,
	})
}

func (s *server) uploadEmployeeI9(w http.ResponseWriter, r *http.Request, number, timePunchName string) {
	emp, err := s.store.getLocationEmployee(r.Context(), number, timePunchName)
	if err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "employee not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load employee")
		return
	}
	missing := manualPaperworkRequiredFields(emp)
	if len(missing) > 0 {
		writeError(w, http.StatusBadRequest, "complete required employee fields before manual paperwork upload: "+strings.Join(missing, ", "))
		return
	}
	data, mime, fileName, err := parseUploadedFileWithField(r, "i9_file", 10<<20, []string{"application/pdf"}, "i9 file is required")
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := withSQLiteRetry(func() error {
		return s.store.upsertEmployeeI9Form(r.Context(), number, timePunchName, data, mime, fileName)
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "unable to persist i9 form")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "i9 uploaded"})
}

func (s *server) getEmployeeI9File(w http.ResponseWriter, r *http.Request, number, timePunchName string) {
	versionID := int64(0)
	if raw := strings.TrimSpace(r.URL.Query().Get("version_id")); raw != "" {
		parsed, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || parsed <= 0 {
			writeError(w, http.StatusBadRequest, "invalid version_id")
			return
		}
		versionID = parsed
	}
	var (
		data     []byte
		mime     string
		fileName string
		err      error
	)
	if versionID > 0 {
		data, mime, fileName, err = s.store.getEmployeeI9HistoryFile(r.Context(), number, timePunchName, versionID)
	} else {
		data, mime, fileName, err = s.store.getEmployeeI9File(r.Context(), number, timePunchName)
	}
	if err != nil {
		if errors.Is(err, errNotFound) {
			http.NotFound(w, r)
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load i9 file")
		return
	}
	w.Header().Set("Content-Type", mime)
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	if strings.TrimSpace(fileName) != "" {
		w.Header().Set("Content-Disposition", "inline; filename="+strconv.Quote(fileName))
	}
	_, _ = w.Write(data)
}

func (s *server) listEmployeeI9Documents(w http.ResponseWriter, r *http.Request, number, timePunchName string) {
	if _, err := s.store.getLocationEmployee(r.Context(), number, timePunchName); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "employee not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load employee")
		return
	}
	docs, err := s.store.listEmployeeI9Documents(r.Context(), number, timePunchName)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to load i9 documents")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"count":     len(docs),
		"documents": docs,
	})
}

func (s *server) uploadEmployeeI9Document(w http.ResponseWriter, r *http.Request, number, timePunchName string) {
	emp, err := s.store.getLocationEmployee(r.Context(), number, timePunchName)
	if err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "employee not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load employee")
		return
	}
	missing := manualPaperworkRequiredFields(emp)
	if len(missing) > 0 {
		writeError(w, http.StatusBadRequest, "complete required employee fields before manual paperwork upload: "+strings.Join(missing, ", "))
		return
	}
	data, mime, fileName, err := parseUploadedFileWithField(
		r,
		"document_file",
		10<<20,
		[]string{"application/pdf", "image/png", "image/jpeg", "image/webp"},
		"document file is required",
	)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	listType := strings.ToLower(strings.TrimSpace(r.FormValue("list_type")))
	switch listType {
	case "a", "b", "c", "other":
	default:
		listType = "other"
	}
	documentTitle := strings.TrimSpace(r.FormValue("document_title"))
	if documentTitle == "" {
		documentTitle = fileName
	}
	issuingAuthority := strings.TrimSpace(r.FormValue("issuing_authority"))
	documentNumber := strings.TrimSpace(r.FormValue("document_number"))
	expirationDate := strings.TrimSpace(r.FormValue("expiration_date"))
	if err := withSQLiteRetry(func() error {
		return s.store.addEmployeeI9Document(
			r.Context(),
			number,
			timePunchName,
			listType,
			documentTitle,
			issuingAuthority,
			documentNumber,
			expirationDate,
			data,
			mime,
			fileName,
		)
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "unable to persist i9 document")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"message": "i9 document uploaded"})
}

func (s *server) getEmployeeI9DocumentFile(w http.ResponseWriter, r *http.Request, number, timePunchName string, docID int64) {
	data, mime, fileName, err := s.store.getEmployeeI9DocumentFile(r.Context(), number, timePunchName, docID)
	if err != nil {
		if errors.Is(err, errNotFound) {
			http.NotFound(w, r)
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load i9 document")
		return
	}
	w.Header().Set("Content-Type", mime)
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	if strings.TrimSpace(fileName) != "" {
		w.Header().Set("Content-Disposition", "inline; filename="+strconv.Quote(fileName))
	}
	_, _ = w.Write(data)
}

func (s *server) deleteEmployeeI9Document(w http.ResponseWriter, r *http.Request, number, timePunchName string, docID int64) {
	if err := withSQLiteRetry(func() error {
		return s.store.deleteEmployeeI9Document(r.Context(), number, timePunchName, docID)
	}); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "i9 document not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to delete i9 document")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "document deleted"})
}

func (s *server) getArchivedEmployeeI9(w http.ResponseWriter, r *http.Request, number, timePunchName string) {
	archived, err := s.store.getArchivedEmployeeRecord(r.Context(), number, timePunchName)
	if err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "archived employee not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load archived employee")
		return
	}
	form, err := s.store.getArchivedEmployeeI9Form(r.Context(), archived.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to load i9 form")
		return
	}
	docs, err := s.store.listArchivedEmployeeI9Documents(r.Context(), archived.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to load i9 documents")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"i9":        form,
		"paperwork": form,
		"documents": docs,
	})
}

func (s *server) getArchivedEmployeeI9File(w http.ResponseWriter, r *http.Request, number, timePunchName string) {
	archived, err := s.store.getArchivedEmployeeRecord(r.Context(), number, timePunchName)
	if err != nil {
		if errors.Is(err, errNotFound) {
			http.NotFound(w, r)
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load archived employee")
		return
	}
	data, mime, fileName, err := s.store.getArchivedEmployeeI9File(r.Context(), archived.ID)
	if err != nil {
		if errors.Is(err, errNotFound) {
			http.NotFound(w, r)
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load i9 file")
		return
	}
	w.Header().Set("Content-Type", mime)
	w.Header().Set("Cache-Control", "private, max-age=120")
	if strings.TrimSpace(fileName) != "" {
		w.Header().Set("Content-Disposition", "inline; filename="+strconv.Quote(fileName))
	}
	_, _ = w.Write(data)
}

func (s *server) getArchivedEmployeeI9DocumentFile(w http.ResponseWriter, r *http.Request, number, timePunchName string, docID int64) {
	archived, err := s.store.getArchivedEmployeeRecord(r.Context(), number, timePunchName)
	if err != nil {
		if errors.Is(err, errNotFound) {
			http.NotFound(w, r)
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load archived employee")
		return
	}
	data, mime, fileName, err := s.store.getArchivedEmployeeI9DocumentFile(r.Context(), archived.ID, docID)
	if err != nil {
		if errors.Is(err, errNotFound) {
			http.NotFound(w, r)
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load i9 document")
		return
	}
	w.Header().Set("Content-Type", mime)
	w.Header().Set("Cache-Control", "private, max-age=120")
	if strings.TrimSpace(fileName) != "" {
		w.Header().Set("Content-Disposition", "inline; filename="+strconv.Quote(fileName))
	}
	_, _ = w.Write(data)
}

func (s *server) getEmployeeW4(w http.ResponseWriter, r *http.Request, number, timePunchName string) {
	if _, err := s.store.getLocationEmployee(r.Context(), number, timePunchName); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "employee not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load employee")
		return
	}
	form, err := s.store.getEmployeeW4Form(r.Context(), number, timePunchName)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to load w4 form")
		return
	}
	history, err := s.store.listEmployeeW4FormHistory(r.Context(), number, timePunchName)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to load w4 history")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"paperwork": form,
		"history":   history,
	})
}

func (s *server) uploadEmployeeW4(w http.ResponseWriter, r *http.Request, number, timePunchName string) {
	emp, err := s.store.getLocationEmployee(r.Context(), number, timePunchName)
	if err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "employee not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load employee")
		return
	}
	missing := manualPaperworkRequiredFields(emp)
	if len(missing) > 0 {
		writeError(w, http.StatusBadRequest, "complete required employee fields before manual paperwork upload: "+strings.Join(missing, ", "))
		return
	}
	data, mime, fileName, err := parseUploadedFileWithField(r, "w4_file", 10<<20, []string{"application/pdf"}, "w4 file is required")
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := withSQLiteRetry(func() error {
		return s.store.upsertEmployeeW4Form(r.Context(), number, timePunchName, data, mime, fileName)
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "unable to persist w4 form")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "w4 uploaded"})
}

func (s *server) applyPaperworkDefaults(ctx context.Context, locationNumber string, values url.Values) {
	if values == nil {
		return
	}
	today := time.Now().Format("01/02/2006")
	values.Set("employee_signature_date", today)
	values.Set("first_day_employed", today)
	values.Set("employer_signature_date", today)
	values.Set("date", today)

	settings, err := s.store.getLocationSettings(ctx, locationNumber)
	if err != nil {
		return
	}
	businessName := strings.TrimSpace(settings.BusinessName)
	if businessName == "" {
		businessName = strings.TrimSpace(settings.W4EmployerName)
	}
	businessStreet := strings.TrimSpace(settings.BusinessStreet)
	if businessStreet == "" {
		businessStreet = strings.TrimSpace(settings.W4EmployerStreet)
	}
	businessCity := strings.TrimSpace(settings.BusinessCity)
	if businessCity == "" {
		businessCity = strings.TrimSpace(settings.W4EmployerCity)
	}
	businessState := strings.TrimSpace(settings.BusinessState)
	if businessState == "" {
		businessState = strings.TrimSpace(settings.W4EmployerState)
	}
	businessEIN := strings.TrimSpace(settings.BusinessEIN)
	if businessEIN == "" {
		businessEIN = strings.TrimSpace(settings.W4EmployerEIN)
	}
	businessAddress := composeBusinessAddress(businessStreet, businessCity, businessState)
	if businessAddress == "" {
		businessAddress = strings.TrimSpace(settings.W4EmployerAddress)
	}
	sig := strings.TrimSpace(settings.EmployerRepSignature)
	if sig == "" {
		sig = businessName
	}
	if sig != "" {
		values.Set("employer_name_title", sig)
		values.Set("employer_signature", sig)
	}
	if businessName != "" {
		values.Set("employer_business_name", businessName)
	}
	if businessAddress != "" {
		values.Set("employer_business_address", businessAddress)
	}
	// W-4 employer line should use owner/operator + store physical address.
	w4EmployerNameAddr := composeW4EmployerNameAddress(sig, businessAddress)
	values.Set("employer_name_addr", w4EmployerNameAddr)
	if businessEIN != "" {
		values.Set("employer_ein", businessEIN)
	}
	values.Set("employer_date", today)
}

func composeW4EmployerNameAddress(name, address string) string {
	name = strings.TrimSpace(name)
	address = strings.TrimSpace(address)
	if name == "" {
		return address
	}
	if address == "" {
		return name
	}
	return name + ", " + address
}

func composeBusinessAddress(street, city, state string) string {
	street = strings.TrimSpace(street)
	city = strings.TrimSpace(city)
	state = strings.TrimSpace(state)
	parts := make([]string, 0, 3)
	if street != "" {
		parts = append(parts, street)
	}
	if city != "" {
		parts = append(parts, city)
	}
	if state != "" {
		parts = append(parts, state)
	}
	return strings.Join(parts, ", ")
}

func splitBusinessAddressParts(address string) (string, string, string) {
	address = strings.TrimSpace(address)
	if address == "" {
		return "", "", ""
	}
	parts := strings.Split(address, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	if len(parts) >= 3 {
		street := strings.Join(parts[:len(parts)-2], ", ")
		city := parts[len(parts)-2]
		state := parts[len(parts)-1]
		return strings.TrimSpace(street), city, state
	}
	if len(parts) == 2 {
		return parts[0], parts[1], ""
	}
	return parts[0], "", ""
}

func (s *server) getEmployeeW4File(w http.ResponseWriter, r *http.Request, number, timePunchName string) {
	versionID := int64(0)
	if raw := strings.TrimSpace(r.URL.Query().Get("version_id")); raw != "" {
		parsed, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || parsed <= 0 {
			writeError(w, http.StatusBadRequest, "invalid version_id")
			return
		}
		versionID = parsed
	}
	var (
		data     []byte
		mime     string
		fileName string
		err      error
	)
	if versionID > 0 {
		data, mime, fileName, err = s.store.getEmployeeW4HistoryFile(r.Context(), number, timePunchName, versionID)
	} else {
		data, mime, fileName, err = s.store.getEmployeeW4File(r.Context(), number, timePunchName)
	}
	if err != nil {
		if errors.Is(err, errNotFound) {
			http.NotFound(w, r)
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load w4 file")
		return
	}
	w.Header().Set("Content-Type", mime)
	w.Header().Set("Cache-Control", "private, max-age=120")
	if strings.TrimSpace(fileName) != "" {
		w.Header().Set("Content-Disposition", "inline; filename="+strconv.Quote(fileName))
	}
	_, _ = w.Write(data)
}

func (s *server) getArchivedEmployeeW4(w http.ResponseWriter, r *http.Request, number, timePunchName string) {
	archived, err := s.store.getArchivedEmployeeRecord(r.Context(), number, timePunchName)
	if err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "archived employee not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load archived employee")
		return
	}
	form, err := s.store.getArchivedEmployeeW4Form(r.Context(), archived.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to load w4 form")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"paperwork": form,
	})
}

func (s *server) getArchivedEmployeeW4File(w http.ResponseWriter, r *http.Request, number, timePunchName string) {
	archived, err := s.store.getArchivedEmployeeRecord(r.Context(), number, timePunchName)
	if err != nil {
		if errors.Is(err, errNotFound) {
			http.NotFound(w, r)
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load archived employee")
		return
	}
	data, mime, fileName, err := s.store.getArchivedEmployeeW4File(r.Context(), archived.ID)
	if err != nil {
		if errors.Is(err, errNotFound) {
			http.NotFound(w, r)
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load w4 file")
		return
	}
	w.Header().Set("Content-Type", mime)
	w.Header().Set("Cache-Control", "private, max-age=120")
	if strings.TrimSpace(fileName) != "" {
		w.Header().Set("Content-Disposition", "inline; filename="+strconv.Quote(fileName))
	}
	_, _ = w.Write(data)
}

func (s *server) importLocationEmployees(w http.ResponseWriter, r *http.Request, number string) {
	file, header, err := r.FormFile("bio_file")
	if err != nil {
		writeError(w, http.StatusBadRequest, "employee bio reader file is required")
		return
	}
	defer file.Close()

	parsedRows, err := parseBioEmployeesFromSpreadsheet(file, header.Filename)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if _, err := s.store.getLocationByNumber(r.Context(), number); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "location not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load location")
		return
	}
	existing, err := s.store.listLocationEmployees(r.Context(), number)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to load employees")
		return
	}
	employeesByKey := make(map[string]employee, len(existing))
	employeesByNumber := make(map[string]employee, len(existing))
	for _, e := range existing {
		employeesByKey[e.TimePunchName] = e
		if strings.TrimSpace(e.EmployeeNumber) != "" {
			employeesByNumber[strings.TrimSpace(e.EmployeeNumber)] = e
		}
	}

	updated := 0
	terminated := 0
	archived := 0

	activeByKey := make(map[string]struct{})
	terminatedByKey := make(map[string]struct{})
	for _, incoming := range parsedRows {
		matchKey := ""
		if strings.TrimSpace(incoming.EmployeeNumber) != "" {
			if currentByNumber, found := employeesByNumber[strings.TrimSpace(incoming.EmployeeNumber)]; found {
				matchKey = currentByNumber.TimePunchName
			}
		}
		if matchKey == "" {
			if currentByName, found := employeesByKey[incoming.TimePunchName]; found {
				matchKey = currentByName.TimePunchName
			}
		}

		if incoming.Terminated {
			if matchKey == "" {
				continue
			}
			if _, alreadyTerminated := terminatedByKey[matchKey]; alreadyTerminated {
				continue
			}
			if err := withSQLiteRetry(func() error {
				return s.store.archiveAndDeleteLocationEmployee(r.Context(), number, matchKey)
			}); err != nil {
				writeError(w, http.StatusInternalServerError, "unable to archive terminated employees")
				return
			}
			terminatedByKey[matchKey] = struct{}{}
			delete(employeesByKey, matchKey)
			terminated++
			continue
		}

		current, found := employeesByKey[matchKey]
		if !found {
			// Candidate workflow is the only allowed employee creation path.
			// Unknown bio rows are ignored instead of creating new employee records.
			continue
		}

		changed := false
		if strings.TrimSpace(incoming.EmployeeNumber) != "" && strings.TrimSpace(current.EmployeeNumber) != strings.TrimSpace(incoming.EmployeeNumber) {
			current.EmployeeNumber = strings.TrimSpace(incoming.EmployeeNumber)
			changed = true
		}
		if current.FirstName != incoming.FirstName {
			current.FirstName = incoming.FirstName
			changed = true
		}
		if current.LastName != incoming.LastName {
			current.LastName = incoming.LastName
			changed = true
		}
		if strings.TrimSpace(current.Department) == "" {
			current.Department = "INIT"
			changed = true
		}
		if changed {
			if err := withSQLiteRetry(func() error {
				return s.store.upsertLocationEmployee(r.Context(), number, current)
			}); err != nil {
				writeError(w, http.StatusInternalServerError, "unable to persist employees: "+err.Error())
				return
			}
			employeesByKey[current.TimePunchName] = current
			updated++
		}
		if strings.TrimSpace(current.EmployeeNumber) != "" {
			employeesByNumber[strings.TrimSpace(current.EmployeeNumber)] = current
		}
		activeByKey[current.TimePunchName] = struct{}{}
	}

	for _, existingEmployee := range existing {
		if _, ok := activeByKey[existingEmployee.TimePunchName]; ok {
			continue
		}
		if _, ok := terminatedByKey[existingEmployee.TimePunchName]; ok {
			continue
		}
		if err := withSQLiteRetry(func() error {
			return s.store.archiveAndDeleteLocationEmployee(r.Context(), number, existingEmployee.TimePunchName)
		}); err != nil {
			writeError(w, http.StatusInternalServerError, "unable to archive removed employees")
			return
		}
		archived++
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"message":    "employee bio reader imported",
		"added":      0,
		"updated":    updated,
		"terminated": terminated,
		"archived":   archived,
		"count":      len(activeByKey),
	})
}

func (s *server) importLocationBirthdates(w http.ResponseWriter, r *http.Request, number string) {
	file, header, err := r.FormFile("birthdate_file")
	if err != nil {
		writeError(w, http.StatusBadRequest, "employee birthday report file is required")
		return
	}
	defer file.Close()

	rows, err := parseBirthdatesFromSpreadsheet(file, header.Filename)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if _, err := s.store.getLocationByNumber(r.Context(), number); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "location not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load location")
		return
	}
	existing, err := s.store.listLocationEmployees(r.Context(), number)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to load employees")
		return
	}
	employeesByKey := make(map[string]employee, len(existing))
	for _, e := range existing {
		employeesByKey[e.TimePunchName] = e
	}

	updated := 0
	for _, row := range rows {
		current, ok := employeesByKey[row.TimePunchName]
		if !ok {
			continue
		}
		if current.Birthday == row.Birthday {
			continue
		}
		current.Birthday = row.Birthday
		employeesByKey[row.TimePunchName] = current
		if err := withSQLiteRetry(func() error {
			return s.store.upsertLocationEmployee(r.Context(), number, current)
		}); err != nil {
			writeError(w, http.StatusInternalServerError, "unable to persist birthdays: "+err.Error())
			return
		}
		updated++
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"message": "employee birthday report imported",
		"updated": updated,
	})
}

func (s *server) listLocations(w http.ResponseWriter, r *http.Request) {
	page := parsePositiveInt(r.URL.Query().Get("page"), 1)
	perPage := parsePositiveInt(r.URL.Query().Get("per_page"), defaultPerPage)
	if perPage > maxPerPage {
		perPage = maxPerPage
	}

	locations, err := s.store.listLocations(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to load locations")
		return
	}
	currentUser := userFromContext(r.Context())
	if currentUser != nil && !currentUser.IsAdmin {
		filtered := make([]location, 0, 1)
		for _, loc := range locations {
			if strings.TrimSpace(loc.Number) == strings.TrimSpace(currentUser.LocationNumber) {
				filtered = append(filtered, loc)
				break
			}
		}
		locations = filtered
	}
	total := len(locations)
	totalPages := 1
	if total > 0 {
		totalPages = (total + perPage - 1) / perPage
	}
	if page > totalPages {
		page = totalPages
	}

	start := (page - 1) * perPage
	if start > total {
		start = total
	}
	end := start + perPage
	if end > total {
		end = total
	}

	// Show newest first on admin table.
	paged := make([]location, 0, end-start)
	for i := end - 1; i >= start; i-- {
		paged = append(paged, locations[i])
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"count":      total,
		"page":       page,
		"perPage":    perPage,
		"totalPages": totalPages,
		"locations":  paged,
	})
}

func (s *server) createLocation(w http.ResponseWriter, r *http.Request) {
	var req createLocationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.Number = strings.TrimSpace(req.Number)
	req.Email = locationLoginEmail(req.Number)
	if err := validateCreateLocation(req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	restaurantPassword := locationDefaultPassword(req.Number)

	entry := location{
		Name:      strings.TrimSpace(req.Name),
		Number:    req.Number,
		Email:     strings.TrimSpace(req.Email),
		Phone:     strings.TrimSpace(req.Phone),
		CreatedAt: time.Now().UTC(),
	}
	if err := s.store.createLocation(r.Context(), entry); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			writeError(w, http.StatusConflict, "location number already exists")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to persist location")
		return
	}
	if err := withSQLiteRetry(func() error {
		return s.store.ensureDefaultDepartmentsAndJobs(r.Context(), entry.Number)
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "location created but unable to seed default departments and jobs")
		return
	}
	if err := withSQLiteRetry(func() error {
		for idx, interviewType := range defaultLocationInterviewTypes {
			_, err := s.store.createCandidateInterviewName(r.Context(), candidateInterviewName{
				LocationNumber: entry.Number,
				Name:           interviewType,
				Priority:       int64(idx + 1),
			})
			if err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "location created but unable to seed default interview types")
		return
	}
	if err := withSQLiteRetry(func() error {
		employerRepSignature := strings.TrimSpace(req.EmployerRepSignature)
		businessStreet := strings.TrimSpace(req.BusinessStreet)
		businessCity := strings.TrimSpace(req.BusinessCity)
		businessState := strings.TrimSpace(req.BusinessState)
		businessEIN := strings.TrimSpace(req.BusinessEIN)
		if businessStreet == "" && businessCity == "" && businessState == "" {
			businessStreet, businessCity, businessState = splitBusinessAddressParts(req.BusinessAddress)
		}
		businessAddress := composeBusinessAddress(businessStreet, businessCity, businessState)
		return s.store.upsertLocationSettings(r.Context(), locationSettings{
			LocationNumber:       entry.Number,
			EmployerRepSignature: employerRepSignature,
			BusinessName:         strings.TrimSpace(req.BusinessName),
			BusinessStreet:       businessStreet,
			BusinessCity:         businessCity,
			BusinessState:        businessState,
			BusinessEIN:          businessEIN,
			BusinessAddress:      businessAddress,
			W4EmployerName:       strings.TrimSpace(req.BusinessName),
			W4EmployerStreet:     businessStreet,
			W4EmployerCity:       businessCity,
			W4EmployerState:      businessState,
			W4EmployerEIN:        businessEIN,
			W4EmployerAddress:    businessAddress,
			Departments:          []string{"INIT"},
			RestaurantUsername:   entry.Email,
		})
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "location created but unable to persist default settings")
		return
	}
	if err := withSQLiteRetry(func() error {
		return s.store.upsertRestaurantUser(r.Context(), entry.Number, entry.Email, restaurantPassword)
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "location created but unable to configure restaurant login")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"message":            "location created",
		"location":           entry,
		"restaurantUsername": entry.Email,
		"restaurantPassword": restaurantPassword,
	})
}

func (s *server) updateLocation(w http.ResponseWriter, r *http.Request, number string) {
	if !isAdminUser(r.Context()) {
		writeError(w, http.StatusForbidden, "admin access required")
		return
	}
	if _, err := s.store.getLocationByNumber(r.Context(), number); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "location not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load location")
		return
	}

	var req updateLocationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}

	if err := s.store.updateLocationName(r.Context(), number, name); err != nil {
		writeError(w, http.StatusInternalServerError, "unable to persist location")
		return
	}
	loc, err := s.store.getLocationByNumber(r.Context(), number)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to load location")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"message":  "location updated",
		"location": loc,
	})
}

func (s *server) deleteLocation(w http.ResponseWriter, r *http.Request, number string) {
	if !isAdminUser(r.Context()) {
		writeError(w, http.StatusForbidden, "admin access required")
		return
	}
	var req deleteLocationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if strings.TrimSpace(req.ConfirmationText) != deleteLocationConfirmationPhrase {
		writeError(w, http.StatusBadRequest, "confirmation phrase mismatch")
		return
	}
	if err := s.store.deleteLocation(r.Context(), number); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "location not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to delete location")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "location deleted"})
}

func (s *server) updateEmployeeDepartment(w http.ResponseWriter, r *http.Request, number, timePunchName string) {
	if _, err := s.store.getLocationByNumber(r.Context(), number); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "location not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load location")
		return
	}

	var req updateEmployeeDepartmentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	department := strings.ToUpper(strings.TrimSpace(req.Department))
	settings, err := s.store.getLocationSettings(r.Context(), number)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to load location settings")
		return
	}
	if _, ok := departmentsSet(settings.Departments)[department]; !ok {
		writeError(w, http.StatusBadRequest, "invalid department")
		return
	}

	if err := s.store.updateLocationEmployeeDepartment(r.Context(), number, timePunchName, department); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "employee not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to persist employee department")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"message":    "department updated",
		"department": department,
	})
}

func (s *server) updateEmployeeJob(w http.ResponseWriter, r *http.Request, number, timePunchName string) {
	if _, err := s.store.getLocationByNumber(r.Context(), number); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "location not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load location")
		return
	}

	var req updateEmployeeJobRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.JobID <= 0 {
		writeError(w, http.StatusBadRequest, "pay band is required")
		return
	}
	job, err := s.store.getLocationJobByID(r.Context(), number, req.JobID)
	if err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusBadRequest, "invalid pay band")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load pay band")
		return
	}
	payType := strings.ToLower(strings.TrimSpace(job.PayType))
	if payType != "hourly" && payType != "salary" {
		writeError(w, http.StatusBadRequest, "selected pay band has an invalid pay type")
		return
	}
	if job.PayAmountCents <= 0 {
		writeError(w, http.StatusBadRequest, "selected pay band has an invalid pay amount")
		return
	}
	if err := s.store.updateLocationEmployeeJob(r.Context(), number, timePunchName, req.JobID, "", payType, job.PayAmountCents); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "employee not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to persist employee pay band")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"message":        "pay band updated",
		"payBandId":      req.JobID,
		"payBandName":    job.Name,
		"payType":        payType,
		"payAmountCents": job.PayAmountCents,
	})
}

func (s *server) updateEmployeePayBand(w http.ResponseWriter, r *http.Request, number, timePunchName string) {
	if _, err := s.store.getLocationByNumber(r.Context(), number); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "location not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load location")
		return
	}
	var req updateEmployeePayBandRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.PayBandID <= 0 {
		writeError(w, http.StatusBadRequest, "pay band is required")
		return
	}
	payBand, err := s.store.getLocationJobByID(r.Context(), number, req.PayBandID)
	if err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusBadRequest, "invalid pay band")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load pay band")
		return
	}
	payType := strings.ToLower(strings.TrimSpace(payBand.PayType))
	if payType != "hourly" && payType != "salary" {
		writeError(w, http.StatusBadRequest, "selected pay band has an invalid pay type")
		return
	}
	if payBand.PayAmountCents <= 0 {
		writeError(w, http.StatusBadRequest, "selected pay band has an invalid pay amount")
		return
	}
	if err := s.store.updateLocationEmployeeJob(r.Context(), number, timePunchName, req.PayBandID, "", payType, payBand.PayAmountCents); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "employee not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to persist employee pay band")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"message":       "pay band updated",
		"payBandId":     payBand.ID,
		"payBandName":   payBand.Name,
		"payType":       payType,
		"payAmountCents": payBand.PayAmountCents,
	})
}

func (s *server) addEmployeeAdditionalCompensation(w http.ResponseWriter, r *http.Request, number, timePunchName string) {
	if _, err := s.store.getLocationEmployee(r.Context(), number, timePunchName); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "employee not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load employee")
		return
	}
	var req createEmployeeAdditionalCompensationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	label := strings.TrimSpace(req.Label)
	if label == "" {
		writeError(w, http.StatusBadRequest, "label is required")
		return
	}
	_, amountCents, err := parseAndValidateEmployeePay("hourly", req.Amount)
	if err != nil {
		writeError(w, http.StatusBadRequest, "amount must be a positive dollar value")
		return
	}
	comp, err := s.store.addEmployeeAdditionalCompensation(r.Context(), number, timePunchName, label, amountCents)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to save additional compensation")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"message":      "additional compensation added",
		"compensation": comp,
	})
}

func (s *server) deleteEmployeeAdditionalCompensation(w http.ResponseWriter, r *http.Request, number, timePunchName string, compensationID int64) {
	if err := s.store.deleteEmployeeAdditionalCompensation(r.Context(), number, timePunchName, compensationID); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "compensation not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to delete additional compensation")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "additional compensation deleted"})
}

func (s *server) listEmployeeAdditionalCompensations(w http.ResponseWriter, r *http.Request, number, timePunchName string) {
	if _, err := s.store.getLocationEmployee(r.Context(), number, timePunchName); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "employee not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load employee")
		return
	}
	list, err := s.store.listEmployeeAdditionalCompensations(r.Context(), number, timePunchName)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to load additional compensations")
		return
	}
	total := int64(0)
	for _, item := range list {
		total += item.AmountCents
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"count":         len(list),
		"totalCents":    total,
		"compensations": list,
	})
}

func (s *server) updateLocationEmployeeClockInPIN(w http.ResponseWriter, r *http.Request, number, timePunchName string) {
	if _, err := s.store.getLocationEmployee(r.Context(), number, timePunchName); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "employee not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load employee")
		return
	}
	var req updateEmployeeClockInPINRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.PIN = strings.TrimSpace(req.PIN)
	if len(req.PIN) < 5 || len(req.PIN) > 6 {
		writeError(w, http.StatusBadRequest, "pin must be 5 or 6 digits")
		return
	}
	for _, ch := range req.PIN {
		if ch < '0' || ch > '9' {
			writeError(w, http.StatusBadRequest, "pin must be 5 or 6 digits")
			return
		}
	}
	if err := withSQLiteRetry(func() error {
		return s.store.upsertTeamMemberPIN(r.Context(), number, timePunchName, req.PIN)
	}); err != nil {
		if errors.Is(err, errPINInUse) {
			writeError(w, http.StatusBadRequest, "this pin is already assigned to another team member at this location")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to save clock in pin")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "clock in pin saved"})
}

func (s *server) updateLocationEmployeeDetails(w http.ResponseWriter, r *http.Request, number, timePunchName string) {
	if _, err := s.store.getLocationByNumber(r.Context(), number); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "location not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load location")
		return
	}
	current, err := s.store.getLocationEmployee(r.Context(), number, timePunchName)
	if err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "employee not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load employee")
		return
	}

	var req updateEmployeeDetailsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	firstName := strings.TrimSpace(req.FirstName)
	lastName := strings.TrimSpace(req.LastName)
	if firstName == "" || lastName == "" {
		writeError(w, http.StatusBadRequest, "first name and last name are required")
		return
	}

	payType := strings.TrimSpace(current.PayType)
	payAmountCents := current.PayAmountCents
	if strings.TrimSpace(req.PayType) != "" || strings.TrimSpace(req.PayAmount) != "" {
		parsedPayType, parsedPayAmountCents, err := parseAndValidateEmployeePay(req.PayType, req.PayAmount)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		payType = parsedPayType
		payAmountCents = parsedPayAmountCents
	}

	birthday := strings.TrimSpace(req.Birthday)
	if birthday != "" {
		normalized, ok := normalizeBirthday(birthday)
		if !ok {
			writeError(w, http.StatusBadRequest, "birthday must be a valid date")
			return
		}
		birthday = normalized
	}

	updated := *current
	updated.FirstName = firstName
	updated.LastName = lastName
	updated.Birthday = birthday
	updated.Email = strings.TrimSpace(req.Email)
	updated.Phone = strings.TrimSpace(req.Phone)
	updated.Address = strings.TrimSpace(req.Address)
	updated.AptNumber = strings.TrimSpace(req.AptNumber)
	updated.City = strings.TrimSpace(req.City)
	updated.State = strings.TrimSpace(req.State)
	updated.ZipCode = strings.TrimSpace(req.ZipCode)
	updated.PayType = payType
	updated.PayAmountCents = payAmountCents

	if err := withSQLiteRetry(func() error {
		return s.store.upsertLocationEmployee(r.Context(), number, updated)
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "unable to update employee")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"message":  "employee updated",
		"employee": updated,
	})
}

func (s *server) listLocationDepartments(w http.ResponseWriter, r *http.Request, number string) {
	if _, err := s.store.getLocationByNumber(r.Context(), number); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "location not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load location")
		return
	}
	departments, err := s.store.listLocationDepartments(r.Context(), number)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to load departments")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"count":       len(departments),
		"departments": departments,
	})
}

func (s *server) createLocationDepartment(w http.ResponseWriter, r *http.Request, number string) {
	if _, err := s.store.getLocationByNumber(r.Context(), number); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "location not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load location")
		return
	}
	var req createDepartmentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "department name is required")
		return
	}
	department, err := s.store.createLocationDepartment(r.Context(), number, req.Name)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			writeError(w, http.StatusConflict, "department already exists")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to create department")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"message":    "department created",
		"department": department,
	})
}

func (s *server) listLocationJobs(w http.ResponseWriter, r *http.Request, number string) {
	if _, err := s.store.getLocationByNumber(r.Context(), number); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "location not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load location")
		return
	}
	jobs, err := s.store.listLocationJobs(r.Context(), number)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to load jobs")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"count": len(jobs),
		"jobs":  jobs,
	})
}

func (s *server) createLocationJob(w http.ResponseWriter, r *http.Request, number string) {
	if _, err := s.store.getLocationByNumber(r.Context(), number); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "location not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load location")
		return
	}
	var req createJobRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "pay band name is required")
		return
	}
	payType, payAmountCents, err := parseAndValidateEmployeePay(req.PayType, req.PayAmount)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	job, err := s.store.createLocationJob(r.Context(), number, req.Name, payType, payAmountCents)
	if err != nil {
		switch {
		case strings.Contains(strings.ToLower(err.Error()), "unique"):
			writeError(w, http.StatusConflict, "pay band already exists")
		default:
			writeError(w, http.StatusInternalServerError, "unable to create pay band")
		}
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"message": "pay band created",
		"payBand": job,
	})
}

func (s *server) updateLocationJob(w http.ResponseWriter, r *http.Request, number string, jobID int64) {
	if _, err := s.store.getLocationByNumber(r.Context(), number); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "location not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load location")
		return
	}
	var req createJobRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "pay band name is required")
		return
	}
	payType, payAmountCents, err := parseAndValidateEmployeePay(req.PayType, req.PayAmount)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	updated, err := s.store.updateLocationJob(r.Context(), number, jobID, req.Name, payType, payAmountCents)
	if err != nil {
		switch {
		case errors.Is(err, errNotFound):
			writeError(w, http.StatusNotFound, "pay band not found")
		case strings.Contains(strings.ToLower(err.Error()), "unique"):
			writeError(w, http.StatusConflict, "pay band already exists")
		default:
			writeError(w, http.StatusInternalServerError, "unable to update pay band")
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"message": "pay band updated",
		"payBand": updated,
	})
}

func (s *server) assignLocationJobDepartments(w http.ResponseWriter, r *http.Request, number string, jobID int64) {
	if _, err := s.store.getLocationByNumber(r.Context(), number); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "location not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load location")
		return
	}
	var req assignJobDepartmentsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	departmentIDs := make([]int64, 0, len(req.DepartmentIDs)+1)
	seen := make(map[int64]struct{}, len(req.DepartmentIDs)+1)
	if req.DepartmentID > 0 {
		seen[req.DepartmentID] = struct{}{}
		departmentIDs = append(departmentIDs, req.DepartmentID)
	}
	for _, id := range req.DepartmentIDs {
		if id <= 0 {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		departmentIDs = append(departmentIDs, id)
	}

	var job locationJob
	err := withSQLiteRetry(func() error {
		var assignErr error
		job, assignErr = s.store.assignLocationJobDepartments(r.Context(), number, jobID, departmentIDs)
		return assignErr
	})
	if err != nil {
		switch {
		case errors.Is(err, errNotFound):
			writeError(w, http.StatusNotFound, "job not found")
		case strings.Contains(strings.ToLower(err.Error()), "department"):
			writeError(w, http.StatusBadRequest, err.Error())
		default:
			writeError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"message": "job departments updated",
		"job":     job,
	})
}

func (s *server) getEmployeePhoto(w http.ResponseWriter, r *http.Request, number, timePunchName string) {
	data, mime, err := s.store.getEmployeePhoto(r.Context(), number, timePunchName)
	if err != nil {
		if errors.Is(err, errNotFound) {
			http.NotFound(w, r)
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load photo")
		return
	}
	w.Header().Set("Content-Type", mime)
	w.Header().Set("Cache-Control", "private, max-age=300")
	_, _ = w.Write(data)
}

func (s *server) uploadEmployeePhoto(w http.ResponseWriter, r *http.Request, number, timePunchName string) {
	data, mime, err := parseUploadedPhoto(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := withSQLiteRetry(func() error {
		return s.store.updateEmployeePhoto(r.Context(), number, timePunchName, data, mime)
	}); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "employee not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to persist photo: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "photo uploaded"})
}

func (s *server) createEmployeePhotoLink(w http.ResponseWriter, r *http.Request, number, timePunchName string) {
	if _, err := s.store.getLocationEmployee(r.Context(), number, timePunchName); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "employee not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load employee")
		return
	}
	token, err := randomToken(32)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to generate upload link")
		return
	}
	expiresAt := time.Now().UTC().Add(7 * 24 * time.Hour)
	if err := s.store.createEmployeePhotoToken(r.Context(), token, number, timePunchName, expiresAt); err != nil {
		writeError(w, http.StatusInternalServerError, "unable to persist upload link")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"token":     token,
		"expiresAt": expiresAt.Format(time.RFC3339),
	})
}

func (s *server) createEmployeePaperworkLink(w http.ResponseWriter, r *http.Request, number, timePunchName string) {
	if _, err := s.store.getLocationEmployee(r.Context(), number, timePunchName); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "employee not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load employee")
		return
	}
	token, err := s.store.getOrCreateEmployeePaperworkToken(r.Context(), number, timePunchName)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to generate paperwork link")
		return
	}
	expiresAt := time.Now().UTC().Add(7 * 24 * time.Hour)
	writeJSON(w, http.StatusOK, map[string]string{
		"token":     token,
		"expiresAt": expiresAt.Format(time.RFC3339),
	})
}

func (s *server) requireAuthenticated(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(sessionCookieName)
		if err != nil || strings.TrimSpace(cookie.Value) == "" {
			writeError(w, http.StatusUnauthorized, "authentication required")
			return
		}

		sess, user, err := s.store.lookupSession(r.Context(), cookie.Value)
		if err != nil {
			if errors.Is(err, errNotFound) {
				expireSessionCookie(w)
				writeError(w, http.StatusUnauthorized, "authentication required")
				return
			}
			writeError(w, http.StatusInternalServerError, "session check failed")
			return
		}

		ctx := context.WithValue(r.Context(), sessionContextKey, sess)
		ctx = context.WithValue(ctx, userContextKey, user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *server) requireAdmin(next http.Handler) http.Handler {
	return s.requireAuthenticated(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isAdminUser(r.Context()) {
			writeError(w, http.StatusForbidden, "admin access required")
			return
		}
		next.ServeHTTP(w, r)
	}))
}

func (s *server) csrfProtect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		default:
			next.ServeHTTP(w, r)
			return
		}
		sess := sessionFromContext(r.Context())
		if sess == nil {
			writeError(w, http.StatusUnauthorized, "authentication required")
			return
		}

		token := strings.TrimSpace(r.Header.Get(csrfHeaderName))
		if token == "" || token != sess.CSRFToken {
			writeError(w, http.StatusForbidden, "csrf validation failed")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *sqliteStore) initSchema(ctx context.Context) error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL UNIQUE,
			password_hash TEXT NOT NULL,
			is_admin INTEGER NOT NULL DEFAULT 0,
			role TEXT NOT NULL DEFAULT 'admin',
			access_level TEXT NOT NULL DEFAULT 'no_access',
			location_number TEXT NOT NULL DEFAULT '',
			time_punch_name TEXT NOT NULL DEFAULT '',
			created_at INTEGER NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS sessions (
			id TEXT PRIMARY KEY,
			user_id INTEGER NOT NULL,
			csrf_token TEXT NOT NULL,
			expires_at INTEGER NOT NULL,
			created_at INTEGER NOT NULL,
			last_seen_at INTEGER NOT NULL,
			FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
		);`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);`,
		`CREATE TABLE IF NOT EXISTS locations (
			number TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			email TEXT NOT NULL DEFAULT '',
			phone TEXT NOT NULL DEFAULT '',
			created_at INTEGER NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS location_employees (
			location_number TEXT NOT NULL,
			time_punch_name TEXT NOT NULL,
			employee_number TEXT NOT NULL DEFAULT '',
			first_name TEXT NOT NULL,
			last_name TEXT NOT NULL,
			department TEXT NOT NULL DEFAULT 'INIT',
			job_id INTEGER NOT NULL DEFAULT 0,
			pay_type TEXT NOT NULL DEFAULT '',
			pay_amount_cents INTEGER NOT NULL DEFAULT 0,
			birthday TEXT NOT NULL DEFAULT '',
			email TEXT NOT NULL DEFAULT '',
			phone TEXT NOT NULL DEFAULT '',
			address TEXT NOT NULL DEFAULT '',
			apt_number TEXT NOT NULL DEFAULT '',
			city TEXT NOT NULL DEFAULT '',
			state TEXT NOT NULL DEFAULT '',
			zip_code TEXT NOT NULL DEFAULT '',
			profile_image_data TEXT NOT NULL DEFAULT '',
			profile_image_mime TEXT NOT NULL DEFAULT '',
			PRIMARY KEY(location_number, time_punch_name),
			FOREIGN KEY(location_number) REFERENCES locations(number) ON DELETE CASCADE
		);`,
		`CREATE INDEX IF NOT EXISTS idx_location_employees_location ON location_employees(location_number);`,
		`CREATE TABLE IF NOT EXISTS archived_location_employees (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			location_number TEXT NOT NULL,
			time_punch_name TEXT NOT NULL,
			employee_number TEXT NOT NULL DEFAULT '',
			first_name TEXT NOT NULL,
			last_name TEXT NOT NULL,
			department TEXT NOT NULL DEFAULT 'INIT',
			job_id INTEGER NOT NULL DEFAULT 0,
			pay_type TEXT NOT NULL DEFAULT '',
			pay_amount_cents INTEGER NOT NULL DEFAULT 0,
			birthday TEXT NOT NULL DEFAULT '',
			email TEXT NOT NULL DEFAULT '',
			phone TEXT NOT NULL DEFAULT '',
			address TEXT NOT NULL DEFAULT '',
			apt_number TEXT NOT NULL DEFAULT '',
			city TEXT NOT NULL DEFAULT '',
			state TEXT NOT NULL DEFAULT '',
			zip_code TEXT NOT NULL DEFAULT '',
			profile_image_data TEXT NOT NULL DEFAULT '',
			profile_image_mime TEXT NOT NULL DEFAULT '',
			archived_at INTEGER NOT NULL,
			UNIQUE(location_number, time_punch_name),
			FOREIGN KEY(location_number) REFERENCES locations(number) ON DELETE CASCADE
		);`,
		`CREATE INDEX IF NOT EXISTS idx_archived_location_employees_location ON archived_location_employees(location_number, archived_at DESC);`,
		`CREATE TABLE IF NOT EXISTS employee_i9_forms (
			location_number TEXT NOT NULL,
			time_punch_name TEXT NOT NULL,
			file_data TEXT NOT NULL DEFAULT '',
			file_mime TEXT NOT NULL DEFAULT '',
			file_name TEXT NOT NULL DEFAULT '',
			updated_at INTEGER NOT NULL,
			created_at INTEGER NOT NULL,
			PRIMARY KEY(location_number, time_punch_name),
			FOREIGN KEY(location_number, time_punch_name) REFERENCES location_employees(location_number, time_punch_name) ON DELETE CASCADE
		);`,
		`CREATE TABLE IF NOT EXISTS employee_i9_form_history (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			location_number TEXT NOT NULL,
			time_punch_name TEXT NOT NULL,
			file_data TEXT NOT NULL DEFAULT '',
			file_mime TEXT NOT NULL DEFAULT '',
			file_name TEXT NOT NULL DEFAULT '',
			created_at INTEGER NOT NULL,
			FOREIGN KEY(location_number, time_punch_name) REFERENCES location_employees(location_number, time_punch_name) ON DELETE CASCADE
		);`,
		`CREATE INDEX IF NOT EXISTS idx_employee_i9_form_history_employee ON employee_i9_form_history(location_number, time_punch_name, created_at DESC);`,
		`CREATE TABLE IF NOT EXISTS employee_i9_documents (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			location_number TEXT NOT NULL,
			time_punch_name TEXT NOT NULL,
			list_type TEXT NOT NULL DEFAULT '',
			document_title TEXT NOT NULL DEFAULT '',
			issuing_authority TEXT NOT NULL DEFAULT '',
			document_number TEXT NOT NULL DEFAULT '',
			expiration_date TEXT NOT NULL DEFAULT '',
			file_data TEXT NOT NULL DEFAULT '',
			file_mime TEXT NOT NULL DEFAULT '',
			file_name TEXT NOT NULL DEFAULT '',
			created_at INTEGER NOT NULL,
			FOREIGN KEY(location_number, time_punch_name) REFERENCES location_employees(location_number, time_punch_name) ON DELETE CASCADE
		);`,
		`CREATE INDEX IF NOT EXISTS idx_employee_i9_documents_employee ON employee_i9_documents(location_number, time_punch_name, created_at DESC);`,
		`CREATE TABLE IF NOT EXISTS archived_employee_i9_forms (
			archived_employee_id INTEGER PRIMARY KEY,
			file_data TEXT NOT NULL DEFAULT '',
			file_mime TEXT NOT NULL DEFAULT '',
			file_name TEXT NOT NULL DEFAULT '',
			updated_at INTEGER NOT NULL,
			created_at INTEGER NOT NULL,
			FOREIGN KEY(archived_employee_id) REFERENCES archived_location_employees(id) ON DELETE CASCADE
		);`,
		`CREATE TABLE IF NOT EXISTS archived_employee_i9_documents (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			archived_employee_id INTEGER NOT NULL,
			list_type TEXT NOT NULL DEFAULT '',
			document_title TEXT NOT NULL DEFAULT '',
			issuing_authority TEXT NOT NULL DEFAULT '',
			document_number TEXT NOT NULL DEFAULT '',
			expiration_date TEXT NOT NULL DEFAULT '',
			file_data TEXT NOT NULL DEFAULT '',
			file_mime TEXT NOT NULL DEFAULT '',
			file_name TEXT NOT NULL DEFAULT '',
			created_at INTEGER NOT NULL,
			FOREIGN KEY(archived_employee_id) REFERENCES archived_location_employees(id) ON DELETE CASCADE
		);`,
		`CREATE INDEX IF NOT EXISTS idx_archived_employee_i9_documents_employee ON archived_employee_i9_documents(archived_employee_id, created_at DESC);`,
		`CREATE TABLE IF NOT EXISTS employee_w4_forms (
			location_number TEXT NOT NULL,
			time_punch_name TEXT NOT NULL,
			file_data TEXT NOT NULL DEFAULT '',
			file_mime TEXT NOT NULL DEFAULT '',
			file_name TEXT NOT NULL DEFAULT '',
			updated_at INTEGER NOT NULL,
			created_at INTEGER NOT NULL,
			PRIMARY KEY(location_number, time_punch_name),
			FOREIGN KEY(location_number, time_punch_name) REFERENCES location_employees(location_number, time_punch_name) ON DELETE CASCADE
		);`,
		`CREATE TABLE IF NOT EXISTS employee_w4_form_history (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			location_number TEXT NOT NULL,
			time_punch_name TEXT NOT NULL,
			file_data TEXT NOT NULL DEFAULT '',
			file_mime TEXT NOT NULL DEFAULT '',
			file_name TEXT NOT NULL DEFAULT '',
			created_at INTEGER NOT NULL,
			FOREIGN KEY(location_number, time_punch_name) REFERENCES location_employees(location_number, time_punch_name) ON DELETE CASCADE
		);`,
		`CREATE INDEX IF NOT EXISTS idx_employee_w4_form_history_employee ON employee_w4_form_history(location_number, time_punch_name, created_at DESC);`,
		`CREATE TABLE IF NOT EXISTS archived_employee_w4_forms (
			archived_employee_id INTEGER PRIMARY KEY,
			file_data TEXT NOT NULL DEFAULT '',
			file_mime TEXT NOT NULL DEFAULT '',
			file_name TEXT NOT NULL DEFAULT '',
			updated_at INTEGER NOT NULL,
			created_at INTEGER NOT NULL,
			FOREIGN KEY(archived_employee_id) REFERENCES archived_location_employees(id) ON DELETE CASCADE
		);`,
		`CREATE TABLE IF NOT EXISTS employee_photo_tokens (
			token TEXT PRIMARY KEY,
			location_number TEXT NOT NULL,
			time_punch_name TEXT NOT NULL,
			expires_at INTEGER NOT NULL,
			used_at INTEGER,
			created_at INTEGER NOT NULL,
			FOREIGN KEY(location_number) REFERENCES locations(number) ON DELETE CASCADE
		);`,
		`CREATE INDEX IF NOT EXISTS idx_employee_photo_tokens_expires_at ON employee_photo_tokens(expires_at);`,
		`CREATE TABLE IF NOT EXISTS employee_paperwork_tokens (
			token TEXT PRIMARY KEY,
			location_number TEXT NOT NULL,
			time_punch_name TEXT NOT NULL,
			expires_at INTEGER NOT NULL,
			created_at INTEGER NOT NULL,
			UNIQUE(location_number, time_punch_name),
			FOREIGN KEY(location_number, time_punch_name) REFERENCES location_employees(location_number, time_punch_name) ON DELETE CASCADE
		);`,
		`CREATE INDEX IF NOT EXISTS idx_employee_paperwork_tokens_expires_at ON employee_paperwork_tokens(expires_at);`,
		`CREATE TABLE IF NOT EXISTS document_templates (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			document_type TEXT NOT NULL UNIQUE,
			template_path TEXT NOT NULL DEFAULT '',
			signature_page INTEGER NOT NULL DEFAULT 1,
			signature_top_left_x REAL NOT NULL DEFAULT 0,
			signature_top_left_y REAL NOT NULL DEFAULT 0,
			signature_width REAL NOT NULL DEFAULT 0,
			signature_height REAL NOT NULL DEFAULT 0,
			signature_zoom INTEGER NOT NULL DEFAULT 250,
			form_field_name TEXT NOT NULL DEFAULT '',
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS employee_document_packets (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			location_number TEXT NOT NULL,
			time_punch_name TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'draft',
			finalized_at INTEGER NOT NULL DEFAULT 0,
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL,
			FOREIGN KEY(location_number, time_punch_name) REFERENCES location_employees(location_number, time_punch_name) ON DELETE CASCADE
		);`,
		`CREATE INDEX IF NOT EXISTS idx_employee_document_packets_employee ON employee_document_packets(location_number, time_punch_name, id DESC);`,
		`CREATE TABLE IF NOT EXISTS packet_documents (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			packet_id INTEGER NOT NULL,
			document_type TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'draft',
			file_data TEXT NOT NULL DEFAULT '',
			file_mime TEXT NOT NULL DEFAULT '',
			file_name TEXT NOT NULL DEFAULT '',
			signed_file_data TEXT NOT NULL DEFAULT '',
			signed_file_mime TEXT NOT NULL DEFAULT '',
			signed_file_name TEXT NOT NULL DEFAULT '',
			signature_page INTEGER NOT NULL DEFAULT 1,
			signature_top_left_x REAL NOT NULL DEFAULT 0,
			signature_top_left_y REAL NOT NULL DEFAULT 0,
			signature_width REAL NOT NULL DEFAULT 0,
			signature_height REAL NOT NULL DEFAULT 0,
			signature_zoom INTEGER NOT NULL DEFAULT 250,
			form_field_name TEXT NOT NULL DEFAULT '',
			required_signatures INTEGER NOT NULL DEFAULT 1,
			signed_count INTEGER NOT NULL DEFAULT 0,
			signed_at INTEGER NOT NULL DEFAULT 0,
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL,
			UNIQUE(packet_id, document_type),
			FOREIGN KEY(packet_id) REFERENCES employee_document_packets(id) ON DELETE CASCADE
		);`,
		`CREATE INDEX IF NOT EXISTS idx_packet_documents_packet ON packet_documents(packet_id, id ASC);`,
		`CREATE TABLE IF NOT EXISTS signature_events (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			packet_id INTEGER NOT NULL,
			packet_document_id INTEGER NOT NULL,
			location_number TEXT NOT NULL,
			time_punch_name TEXT NOT NULL,
			signer_name TEXT NOT NULL DEFAULT '',
			signer_ip TEXT NOT NULL DEFAULT '',
			user_agent TEXT NOT NULL DEFAULT '',
			event_type TEXT NOT NULL DEFAULT '',
			signature_index INTEGER NOT NULL DEFAULT 1,
			signature_hash TEXT NOT NULL DEFAULT '',
			created_at INTEGER NOT NULL,
			FOREIGN KEY(packet_id) REFERENCES employee_document_packets(id) ON DELETE CASCADE,
			FOREIGN KEY(packet_document_id) REFERENCES packet_documents(id) ON DELETE CASCADE
		);`,
		`CREATE INDEX IF NOT EXISTS idx_signature_events_packet ON signature_events(packet_id, created_at ASC);`,
		`CREATE TABLE IF NOT EXISTS location_time_punch_tokens (
			token TEXT PRIMARY KEY,
			location_number TEXT NOT NULL UNIQUE,
			created_at INTEGER NOT NULL,
			FOREIGN KEY(location_number) REFERENCES locations(number) ON DELETE CASCADE
		);`,
		`CREATE TABLE IF NOT EXISTS location_time_off_tokens (
			token TEXT PRIMARY KEY,
			location_number TEXT NOT NULL UNIQUE,
			created_at INTEGER NOT NULL,
			FOREIGN KEY(location_number) REFERENCES locations(number) ON DELETE CASCADE
		);`,
		`CREATE TABLE IF NOT EXISTS location_time_punch_entries (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			location_number TEXT NOT NULL,
			time_punch_name TEXT NOT NULL,
			punch_date TEXT NOT NULL,
			time_in TEXT NOT NULL,
			time_out TEXT NOT NULL,
			note TEXT NOT NULL DEFAULT '',
			forgot_break_clock_in_return INTEGER NOT NULL DEFAULT 0,
			archived_at INTEGER NOT NULL DEFAULT 0,
			created_at INTEGER NOT NULL,
			FOREIGN KEY(location_number) REFERENCES locations(number) ON DELETE CASCADE
		);`,
		`CREATE INDEX IF NOT EXISTS idx_time_punch_entries_location_created ON location_time_punch_entries(location_number, created_at DESC);`,
		`CREATE TABLE IF NOT EXISTS location_time_off_requests (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			location_number TEXT NOT NULL,
			time_punch_name TEXT NOT NULL,
			start_date TEXT NOT NULL,
			end_date TEXT NOT NULL,
			archived_at INTEGER NOT NULL DEFAULT 0,
			created_at INTEGER NOT NULL,
			FOREIGN KEY(location_number) REFERENCES locations(number) ON DELETE CASCADE
		);`,
		`CREATE INDEX IF NOT EXISTS idx_time_off_requests_location_created ON location_time_off_requests(location_number, created_at DESC);`,
		`CREATE TABLE IF NOT EXISTS location_business_days (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			location_number TEXT NOT NULL,
			business_date TEXT NOT NULL,
			total_sales REAL NOT NULL DEFAULT 0,
			labor_hours REAL NOT NULL DEFAULT 0,
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL,
			UNIQUE(location_number, business_date),
			FOREIGN KEY(location_number) REFERENCES locations(number) ON DELETE CASCADE
		);`,
		`CREATE INDEX IF NOT EXISTS idx_business_days_location_date ON location_business_days(location_number, business_date DESC);`,
		`CREATE TABLE IF NOT EXISTS location_settings (
			location_number TEXT PRIMARY KEY,
			employer_rep_signature TEXT NOT NULL DEFAULT '',
			w4_employer_name TEXT NOT NULL DEFAULT '',
			w4_employer_street TEXT NOT NULL DEFAULT '',
			w4_employer_city TEXT NOT NULL DEFAULT '',
			w4_employer_state TEXT NOT NULL DEFAULT '',
			w4_employer_ein TEXT NOT NULL DEFAULT '',
			w4_employer_address TEXT NOT NULL DEFAULT '',
			departments_csv TEXT NOT NULL DEFAULT 'INIT',
			restaurant_username TEXT NOT NULL DEFAULT '',
			updated_at INTEGER NOT NULL,
			created_at INTEGER NOT NULL,
			FOREIGN KEY(location_number) REFERENCES locations(number) ON DELETE CASCADE
		);`,
		`CREATE TABLE IF NOT EXISTS location_departments (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			location_number TEXT NOT NULL,
			name TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			UNIQUE(location_number, name),
			FOREIGN KEY(location_number) REFERENCES locations(number) ON DELETE CASCADE
		);`,
		`CREATE INDEX IF NOT EXISTS idx_location_departments_location ON location_departments(location_number, name ASC);`,
		`CREATE TABLE IF NOT EXISTS location_jobs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			location_number TEXT NOT NULL,
			name TEXT NOT NULL,
			pay_type TEXT NOT NULL DEFAULT '',
			pay_amount_cents INTEGER NOT NULL DEFAULT 0,
			created_at INTEGER NOT NULL,
			UNIQUE(location_number, name),
			FOREIGN KEY(location_number) REFERENCES locations(number) ON DELETE CASCADE
		);`,
		`CREATE INDEX IF NOT EXISTS idx_location_jobs_location_name ON location_jobs(location_number, name ASC);`,
		`CREATE TABLE IF NOT EXISTS location_job_departments (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			location_number TEXT NOT NULL,
			job_id INTEGER NOT NULL,
			department_id INTEGER NOT NULL,
			created_at INTEGER NOT NULL,
			UNIQUE(location_number, job_id, department_id),
			FOREIGN KEY(location_number) REFERENCES locations(number) ON DELETE CASCADE,
			FOREIGN KEY(job_id) REFERENCES location_jobs(id) ON DELETE CASCADE,
			FOREIGN KEY(department_id) REFERENCES location_departments(id) ON DELETE CASCADE
		);`,
		`CREATE INDEX IF NOT EXISTS idx_location_job_departments_location_job ON location_job_departments(location_number, job_id, department_id);`,
		`CREATE TABLE IF NOT EXISTS employee_additional_compensations (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			location_number TEXT NOT NULL,
			time_punch_name TEXT NOT NULL,
			label TEXT NOT NULL,
			amount_cents INTEGER NOT NULL DEFAULT 0,
			created_at INTEGER NOT NULL,
			FOREIGN KEY(location_number, time_punch_name) REFERENCES location_employees(location_number, time_punch_name) ON DELETE CASCADE
		);`,
		`CREATE INDEX IF NOT EXISTS idx_employee_additional_compensations_employee ON employee_additional_compensations(location_number, time_punch_name, created_at DESC);`,
		`CREATE TABLE IF NOT EXISTS location_candidate_values (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			location_number TEXT NOT NULL,
			name TEXT NOT NULL,
			description TEXT NOT NULL DEFAULT '',
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL,
			UNIQUE(location_number, name),
			FOREIGN KEY(location_number) REFERENCES locations(number) ON DELETE CASCADE
		);`,
		`CREATE INDEX IF NOT EXISTS idx_candidate_values_location ON location_candidate_values(location_number, id ASC);`,
		`CREATE TABLE IF NOT EXISTS location_candidate_interview_names (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			location_number TEXT NOT NULL,
			name TEXT NOT NULL,
			priority INTEGER NOT NULL DEFAULT 100,
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL,
			UNIQUE(location_number, name),
			FOREIGN KEY(location_number) REFERENCES locations(number) ON DELETE CASCADE
		);`,
		`CREATE INDEX IF NOT EXISTS idx_candidate_interview_names_location ON location_candidate_interview_names(location_number, id ASC);`,
		`CREATE TABLE IF NOT EXISTS location_candidate_interview_questions (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			location_number TEXT NOT NULL,
			interview_name_id INTEGER,
			question TEXT NOT NULL,
			response_type TEXT NOT NULL DEFAULT 'text',
			response_options TEXT NOT NULL DEFAULT '',
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL,
			FOREIGN KEY(location_number) REFERENCES locations(number) ON DELETE CASCADE,
			FOREIGN KEY(interview_name_id) REFERENCES location_candidate_interview_names(id) ON DELETE CASCADE
		);`,
		`CREATE INDEX IF NOT EXISTS idx_candidate_interview_questions_location_name ON location_candidate_interview_questions(location_number, interview_name_id, id ASC);`,
		`CREATE TABLE IF NOT EXISTS location_candidate_interview_question_types (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			question_id INTEGER NOT NULL,
			interview_name_id INTEGER NOT NULL,
			created_at INTEGER NOT NULL,
			UNIQUE(question_id, interview_name_id),
			FOREIGN KEY(question_id) REFERENCES location_candidate_interview_questions(id) ON DELETE CASCADE,
			FOREIGN KEY(interview_name_id) REFERENCES location_candidate_interview_names(id) ON DELETE CASCADE
		);`,
		`CREATE INDEX IF NOT EXISTS idx_candidate_interview_question_types_question ON location_candidate_interview_question_types(question_id, interview_name_id ASC);`,
		`CREATE INDEX IF NOT EXISTS idx_candidate_interview_question_types_name ON location_candidate_interview_question_types(interview_name_id, question_id ASC);`,
		`CREATE TABLE IF NOT EXISTS location_candidates (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			location_number TEXT NOT NULL,
			first_name TEXT NOT NULL,
			last_name TEXT NOT NULL,
			phone TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL DEFAULT 'active',
			hired_time_punch_name TEXT NOT NULL DEFAULT '',
			archived_at INTEGER NOT NULL DEFAULT 0,
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL,
			FOREIGN KEY(location_number) REFERENCES locations(number) ON DELETE CASCADE
		);`,
		`CREATE INDEX IF NOT EXISTS idx_candidates_location_status ON location_candidates(location_number, status, created_at DESC);`,
		`CREATE TABLE IF NOT EXISTS location_candidate_interviews (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			candidate_id INTEGER NOT NULL,
			location_number TEXT NOT NULL,
			interviewer_time_punch_name TEXT NOT NULL,
			interview_type TEXT NOT NULL,
			notes TEXT NOT NULL DEFAULT '',
			created_at INTEGER NOT NULL,
			FOREIGN KEY(candidate_id) REFERENCES location_candidates(id) ON DELETE CASCADE,
			FOREIGN KEY(location_number) REFERENCES locations(number) ON DELETE CASCADE
		);`,
		`CREATE INDEX IF NOT EXISTS idx_candidate_interviews_candidate ON location_candidate_interviews(candidate_id, created_at DESC);`,
		`CREATE TABLE IF NOT EXISTS location_candidate_interview_grades (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			interview_id INTEGER NOT NULL,
			value_id INTEGER NOT NULL,
			letter_grade TEXT NOT NULL,
			grade_comment TEXT NOT NULL DEFAULT '',
			created_at INTEGER NOT NULL,
			UNIQUE(interview_id, value_id),
			FOREIGN KEY(interview_id) REFERENCES location_candidate_interviews(id) ON DELETE CASCADE,
			FOREIGN KEY(value_id) REFERENCES location_candidate_values(id) ON DELETE CASCADE
		);`,
		`CREATE INDEX IF NOT EXISTS idx_candidate_interview_grades_interview ON location_candidate_interview_grades(interview_id, id ASC);`,
		`CREATE TABLE IF NOT EXISTS location_candidate_interview_question_answers (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			interview_id INTEGER NOT NULL,
			question_id INTEGER NOT NULL,
			question_text_snapshot TEXT NOT NULL DEFAULT '',
			answer TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			UNIQUE(interview_id, question_id),
			FOREIGN KEY(interview_id) REFERENCES location_candidate_interviews(id) ON DELETE CASCADE
		);`,
		`CREATE INDEX IF NOT EXISTS idx_candidate_interview_question_answers_interview ON location_candidate_interview_question_answers(interview_id, id ASC);`,
		`CREATE TABLE IF NOT EXISTS location_candidate_interview_tokens (
			token TEXT PRIMARY KEY,
			location_number TEXT NOT NULL,
			candidate_id INTEGER NOT NULL,
			interviewer_time_punch_name TEXT NOT NULL,
			interview_type TEXT NOT NULL,
			scheduled_at INTEGER NOT NULL DEFAULT 0,
			expires_at INTEGER NOT NULL,
			used_at INTEGER NOT NULL DEFAULT 0,
			created_at INTEGER NOT NULL,
			FOREIGN KEY(candidate_id) REFERENCES location_candidates(id) ON DELETE CASCADE,
			FOREIGN KEY(location_number) REFERENCES locations(number) ON DELETE CASCADE
		);`,
		`CREATE INDEX IF NOT EXISTS idx_candidate_interview_tokens_expires ON location_candidate_interview_tokens(expires_at);`,
		`CREATE TABLE IF NOT EXISTS location_uniform_order_tokens (
			token TEXT PRIMARY KEY,
			location_number TEXT NOT NULL UNIQUE,
			created_at INTEGER NOT NULL,
			FOREIGN KEY(location_number) REFERENCES locations(number) ON DELETE CASCADE
		);`,
		`CREATE TABLE IF NOT EXISTS location_uniform_items (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			location_number TEXT NOT NULL,
			name TEXT NOT NULL,
			price_cents INTEGER NOT NULL,
			enabled INTEGER NOT NULL DEFAULT 1,
			system_key TEXT NOT NULL DEFAULT '',
			image_data TEXT NOT NULL DEFAULT '',
			image_mime TEXT NOT NULL DEFAULT '',
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL,
			FOREIGN KEY(location_number) REFERENCES locations(number) ON DELETE CASCADE
		);`,
		`CREATE INDEX IF NOT EXISTS idx_uniform_items_location ON location_uniform_items(location_number, id DESC);`,
		`CREATE TABLE IF NOT EXISTS location_uniform_item_images (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			item_id INTEGER NOT NULL,
			image_data TEXT NOT NULL DEFAULT '',
			image_mime TEXT NOT NULL DEFAULT '',
			sort_order INTEGER NOT NULL DEFAULT 0,
			created_at INTEGER NOT NULL,
			FOREIGN KEY(item_id) REFERENCES location_uniform_items(id) ON DELETE CASCADE
		);`,
		`CREATE INDEX IF NOT EXISTS idx_uniform_item_images_item ON location_uniform_item_images(item_id, sort_order ASC, id ASC);`,
		`CREATE TABLE IF NOT EXISTS location_uniform_item_sizes (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			item_id INTEGER NOT NULL,
			size_label TEXT NOT NULL,
			sort_order INTEGER NOT NULL DEFAULT 0,
			created_at INTEGER NOT NULL,
			UNIQUE(item_id, size_label),
			FOREIGN KEY(item_id) REFERENCES location_uniform_items(id) ON DELETE CASCADE
		);`,
		`CREATE INDEX IF NOT EXISTS idx_uniform_item_sizes_item ON location_uniform_item_sizes(item_id, sort_order ASC, id ASC);`,
		`CREATE TABLE IF NOT EXISTS location_uniform_item_size_options (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			item_id INTEGER NOT NULL,
			field_label TEXT NOT NULL,
			option_value TEXT NOT NULL,
			field_sort_order INTEGER NOT NULL DEFAULT 0,
			option_sort_order INTEGER NOT NULL DEFAULT 0,
			created_at INTEGER NOT NULL,
			UNIQUE(item_id, field_label, option_value),
			FOREIGN KEY(item_id) REFERENCES location_uniform_items(id) ON DELETE CASCADE
		);`,
		`CREATE INDEX IF NOT EXISTS idx_uniform_item_size_options_item ON location_uniform_item_size_options(item_id, field_sort_order ASC, option_sort_order ASC, id ASC);`,
		`CREATE TABLE IF NOT EXISTS location_uniform_orders (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			location_number TEXT NOT NULL,
			time_punch_name TEXT NOT NULL,
			total_cents INTEGER NOT NULL DEFAULT 0,
			archived_at INTEGER NOT NULL DEFAULT 0,
			created_at INTEGER NOT NULL,
			FOREIGN KEY(location_number) REFERENCES locations(number) ON DELETE CASCADE
		);`,
		`CREATE INDEX IF NOT EXISTS idx_uniform_orders_location_created ON location_uniform_orders(location_number, created_at DESC);`,
		`CREATE TABLE IF NOT EXISTS location_uniform_order_lines (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			order_id INTEGER NOT NULL,
			item_id INTEGER NOT NULL,
			item_name TEXT NOT NULL,
			item_number TEXT NOT NULL DEFAULT '',
			size_option TEXT NOT NULL DEFAULT '',
			external_url TEXT NOT NULL DEFAULT '',
			note TEXT NOT NULL DEFAULT '',
			quantity INTEGER NOT NULL,
			unit_price_cents INTEGER NOT NULL,
			line_total_cents INTEGER NOT NULL,
			purchased_at INTEGER NOT NULL DEFAULT 0,
			charged_back_cents INTEGER NOT NULL DEFAULT 0,
			created_at INTEGER NOT NULL,
			FOREIGN KEY(order_id) REFERENCES location_uniform_orders(id) ON DELETE CASCADE,
			FOREIGN KEY(item_id) REFERENCES location_uniform_items(id) ON DELETE CASCADE
		);`,
		`CREATE INDEX IF NOT EXISTS idx_uniform_order_lines_order ON location_uniform_order_lines(order_id);`,
	}

	for _, stmt := range statements {
		if _, err := s.exec(ctx, stmt, nil); err != nil {
			return err
		}
	}
	// Backward-compatible migration for existing databases.
	if _, err := s.exec(ctx, `
		ALTER TABLE users
		ADD COLUMN role TEXT NOT NULL DEFAULT 'admin';
	`, nil); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return err
	}
	if _, err := s.exec(ctx, `
		ALTER TABLE users
		ADD COLUMN access_level TEXT NOT NULL DEFAULT 'no_access';
	`, nil); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return err
	}
	if _, err := s.exec(ctx, `
		ALTER TABLE users
		ADD COLUMN location_number TEXT NOT NULL DEFAULT '';
	`, nil); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return err
	}
	if _, err := s.exec(ctx, `
		ALTER TABLE users
		ADD COLUMN time_punch_name TEXT NOT NULL DEFAULT '';
	`, nil); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return err
	}
	if _, err := s.exec(ctx, `
		UPDATE users
		SET role = CASE
			WHEN is_admin = 1 THEN 'admin'
			WHEN TRIM(COALESCE(role, '')) = '' THEN 'restaurant'
			ELSE role
		END
		WHERE TRIM(COALESCE(role, '')) = '' OR is_admin = 1;
	`, nil); err != nil {
		return err
	}
	if _, err := s.exec(ctx, `
		UPDATE users
		SET access_level = @no_access
		WHERE role = @team_role
			AND TRIM(COALESCE(access_level, '')) = '';
	`, map[string]string{
		"team_role": userRoleTeam,
		"no_access": teamAccessLevelNoAccess,
	}); err != nil {
		return err
	}
	if _, err := s.exec(ctx, `
		ALTER TABLE location_settings
		ADD COLUMN restaurant_username TEXT NOT NULL DEFAULT '';
	`, nil); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return err
	}
	if _, err := s.exec(ctx, `
		ALTER TABLE location_employees
		ADD COLUMN department TEXT NOT NULL DEFAULT 'INIT';
	`, nil); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return err
	}
	if _, err := s.exec(ctx, `
		ALTER TABLE location_employees
		ADD COLUMN profile_image_data TEXT NOT NULL DEFAULT '';
	`, nil); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return err
	}
	if _, err := s.exec(ctx, `
		ALTER TABLE location_employees
		ADD COLUMN job_id INTEGER NOT NULL DEFAULT 0;
	`, nil); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return err
	}
	if _, err := s.exec(ctx, `
		ALTER TABLE location_employees
		ADD COLUMN pay_type TEXT NOT NULL DEFAULT '';
	`, nil); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return err
	}
	if _, err := s.exec(ctx, `
		ALTER TABLE location_employees
		ADD COLUMN pay_amount_cents INTEGER NOT NULL DEFAULT 0;
	`, nil); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return err
	}
	if _, err := s.exec(ctx, `
		ALTER TABLE location_employees
		ADD COLUMN profile_image_mime TEXT NOT NULL DEFAULT '';
	`, nil); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return err
	}
	if _, err := s.exec(ctx, `
		ALTER TABLE location_employees
		ADD COLUMN email TEXT NOT NULL DEFAULT '';
	`, nil); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return err
	}
	if _, err := s.exec(ctx, `
		ALTER TABLE location_employees
		ADD COLUMN phone TEXT NOT NULL DEFAULT '';
	`, nil); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return err
	}
	if _, err := s.exec(ctx, `
		ALTER TABLE location_employees
		ADD COLUMN address TEXT NOT NULL DEFAULT '';
	`, nil); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return err
	}
	if _, err := s.exec(ctx, `
		ALTER TABLE location_employees
		ADD COLUMN apt_number TEXT NOT NULL DEFAULT '';
	`, nil); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return err
	}
	if _, err := s.exec(ctx, `
		ALTER TABLE location_employees
		ADD COLUMN city TEXT NOT NULL DEFAULT '';
	`, nil); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return err
	}
	if _, err := s.exec(ctx, `
		ALTER TABLE location_employees
		ADD COLUMN state TEXT NOT NULL DEFAULT '';
	`, nil); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return err
	}
	if _, err := s.exec(ctx, `
		ALTER TABLE location_employees
		ADD COLUMN zip_code TEXT NOT NULL DEFAULT '';
	`, nil); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return err
	}
	if _, err := s.exec(ctx, `
		ALTER TABLE location_employees
		ADD COLUMN employee_number TEXT NOT NULL DEFAULT '';
	`, nil); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return err
	}
	if _, err := s.exec(ctx, `
		ALTER TABLE location_jobs
		ADD COLUMN pay_type TEXT NOT NULL DEFAULT '';
	`, nil); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return err
	}
	if _, err := s.exec(ctx, `
		ALTER TABLE location_jobs
		ADD COLUMN pay_amount_cents INTEGER NOT NULL DEFAULT 0;
	`, nil); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return err
	}
	if _, err := s.exec(ctx, `
		ALTER TABLE location_candidates
		ADD COLUMN phone TEXT NOT NULL DEFAULT '';
	`, nil); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return err
	}
	if _, err := s.exec(ctx, `
		ALTER TABLE location_candidate_interview_tokens
		ADD COLUMN scheduled_at INTEGER NOT NULL DEFAULT 0;
	`, nil); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return err
	}
	if _, err := s.exec(ctx, `
		UPDATE location_candidate_interview_tokens
		SET scheduled_at = created_at
		WHERE scheduled_at = 0;
	`, nil); err != nil {
		return err
	}
	if _, err := s.exec(ctx, `
		ALTER TABLE archived_location_employees
		ADD COLUMN email TEXT NOT NULL DEFAULT '';
	`, nil); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return err
	}
	if _, err := s.exec(ctx, `
		ALTER TABLE archived_location_employees
		ADD COLUMN job_id INTEGER NOT NULL DEFAULT 0;
	`, nil); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return err
	}
	if _, err := s.exec(ctx, `
		ALTER TABLE archived_location_employees
		ADD COLUMN pay_type TEXT NOT NULL DEFAULT '';
	`, nil); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return err
	}
	if _, err := s.exec(ctx, `
		ALTER TABLE archived_location_employees
		ADD COLUMN pay_amount_cents INTEGER NOT NULL DEFAULT 0;
	`, nil); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return err
	}
	if _, err := s.exec(ctx, `
		ALTER TABLE archived_location_employees
		ADD COLUMN phone TEXT NOT NULL DEFAULT '';
	`, nil); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return err
	}
	if _, err := s.exec(ctx, `
		ALTER TABLE archived_location_employees
		ADD COLUMN address TEXT NOT NULL DEFAULT '';
	`, nil); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return err
	}
	if _, err := s.exec(ctx, `
		ALTER TABLE archived_location_employees
		ADD COLUMN apt_number TEXT NOT NULL DEFAULT '';
	`, nil); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return err
	}
	if _, err := s.exec(ctx, `
		ALTER TABLE archived_location_employees
		ADD COLUMN city TEXT NOT NULL DEFAULT '';
	`, nil); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return err
	}
	if _, err := s.exec(ctx, `
		ALTER TABLE archived_location_employees
		ADD COLUMN state TEXT NOT NULL DEFAULT '';
	`, nil); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return err
	}
	if _, err := s.exec(ctx, `
		ALTER TABLE archived_location_employees
		ADD COLUMN zip_code TEXT NOT NULL DEFAULT '';
	`, nil); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return err
	}
	if _, err := s.exec(ctx, `
		ALTER TABLE archived_location_employees
		ADD COLUMN employee_number TEXT NOT NULL DEFAULT '';
	`, nil); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return err
	}
	if _, err := s.exec(ctx, `
		UPDATE location_employees
		SET department = 'INIT'
		WHERE TRIM(COALESCE(department, '')) = '';
	`, nil); err != nil {
		return err
	}
	if _, err := s.exec(ctx, `
		ALTER TABLE location_uniform_order_lines
		ADD COLUMN size_option TEXT NOT NULL DEFAULT '';
	`, nil); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return err
	}
	if _, err := s.exec(ctx, `
		ALTER TABLE location_uniform_order_lines
		ADD COLUMN note TEXT NOT NULL DEFAULT '';
	`, nil); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return err
	}
	if _, err := s.exec(ctx, `
		ALTER TABLE location_uniform_order_lines
		ADD COLUMN external_url TEXT NOT NULL DEFAULT '';
	`, nil); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return err
	}
	if _, err := s.exec(ctx, `
		ALTER TABLE location_uniform_items
		ADD COLUMN system_key TEXT NOT NULL DEFAULT '';
	`, nil); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return err
	}
	if _, err := s.exec(ctx, `
		CREATE INDEX IF NOT EXISTS idx_uniform_items_system_key
		ON location_uniform_items(location_number, system_key);
	`, nil); err != nil {
		return err
	}
	if _, err := s.exec(ctx, `
		ALTER TABLE locations
		ADD COLUMN email TEXT NOT NULL DEFAULT '';
	`, nil); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return err
	}
	if _, err := s.exec(ctx, `
		ALTER TABLE locations
		ADD COLUMN phone TEXT NOT NULL DEFAULT '';
	`, nil); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return err
	}
	if _, err := s.exec(ctx, `
		ALTER TABLE location_uniform_order_lines
		ADD COLUMN purchased_at INTEGER NOT NULL DEFAULT 0;
	`, nil); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return err
	}
	if _, err := s.exec(ctx, `
		ALTER TABLE location_uniform_order_lines
		ADD COLUMN charged_back_cents INTEGER NOT NULL DEFAULT 0;
	`, nil); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return err
	}
	if _, err := s.exec(ctx, `
		ALTER TABLE location_uniform_orders
		ADD COLUMN archived_at INTEGER NOT NULL DEFAULT 0;
	`, nil); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return err
	}
	if _, err := s.exec(ctx, `
		ALTER TABLE location_time_punch_entries
		ADD COLUMN note TEXT NOT NULL DEFAULT '';
	`, nil); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return err
	}
	if _, err := s.exec(ctx, `
		ALTER TABLE location_time_punch_entries
		ADD COLUMN archived_at INTEGER NOT NULL DEFAULT 0;
	`, nil); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return err
	}
	if _, err := s.exec(ctx, `
		ALTER TABLE location_time_punch_entries
		ADD COLUMN forgot_break_clock_in_return INTEGER NOT NULL DEFAULT 0;
	`, nil); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return err
	}
	if _, err := s.exec(ctx, `
		ALTER TABLE location_settings
		ADD COLUMN departments_csv TEXT NOT NULL DEFAULT 'INIT';
	`, nil); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return err
	}
	if _, err := s.exec(ctx, `
		ALTER TABLE location_settings
		ADD COLUMN w4_employer_name TEXT NOT NULL DEFAULT '';
	`, nil); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return err
	}
	if _, err := s.exec(ctx, `
		ALTER TABLE location_settings
		ADD COLUMN w4_employer_address TEXT NOT NULL DEFAULT '';
	`, nil); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return err
	}
	if _, err := s.exec(ctx, `
		ALTER TABLE location_settings
		ADD COLUMN w4_employer_street TEXT NOT NULL DEFAULT '';
	`, nil); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return err
	}
	if _, err := s.exec(ctx, `
		ALTER TABLE location_settings
		ADD COLUMN w4_employer_city TEXT NOT NULL DEFAULT '';
	`, nil); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return err
	}
	if _, err := s.exec(ctx, `
		ALTER TABLE location_settings
		ADD COLUMN w4_employer_state TEXT NOT NULL DEFAULT '';
	`, nil); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return err
	}
	if _, err := s.exec(ctx, `
		ALTER TABLE location_settings
		ADD COLUMN w4_employer_ein TEXT NOT NULL DEFAULT '';
	`, nil); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return err
	}
	if _, err := s.exec(ctx, `
		ALTER TABLE employee_i9_documents
		ADD COLUMN list_type TEXT NOT NULL DEFAULT '';
	`, nil); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return err
	}
	if _, err := s.exec(ctx, `
		ALTER TABLE archived_employee_i9_documents
		ADD COLUMN list_type TEXT NOT NULL DEFAULT '';
	`, nil); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return err
	}
	if _, err := s.exec(ctx, `
		ALTER TABLE employee_i9_documents
		ADD COLUMN document_title TEXT NOT NULL DEFAULT '';
	`, nil); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return err
	}
	if _, err := s.exec(ctx, `
		ALTER TABLE employee_i9_documents
		ADD COLUMN issuing_authority TEXT NOT NULL DEFAULT '';
	`, nil); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return err
	}
	if _, err := s.exec(ctx, `
		ALTER TABLE employee_i9_documents
		ADD COLUMN document_number TEXT NOT NULL DEFAULT '';
	`, nil); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return err
	}
	if _, err := s.exec(ctx, `
		ALTER TABLE employee_i9_documents
		ADD COLUMN expiration_date TEXT NOT NULL DEFAULT '';
	`, nil); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return err
	}
	if _, err := s.exec(ctx, `
		ALTER TABLE archived_employee_i9_documents
		ADD COLUMN document_title TEXT NOT NULL DEFAULT '';
	`, nil); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return err
	}
	if _, err := s.exec(ctx, `
		ALTER TABLE archived_employee_i9_documents
		ADD COLUMN issuing_authority TEXT NOT NULL DEFAULT '';
	`, nil); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return err
	}
	if _, err := s.exec(ctx, `
		ALTER TABLE archived_employee_i9_documents
		ADD COLUMN document_number TEXT NOT NULL DEFAULT '';
	`, nil); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return err
	}
	if _, err := s.exec(ctx, `
		ALTER TABLE archived_employee_i9_documents
		ADD COLUMN expiration_date TEXT NOT NULL DEFAULT '';
	`, nil); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return err
	}
	if _, err := s.exec(ctx, `
		ALTER TABLE location_candidate_interview_grades
		ADD COLUMN grade_comment TEXT NOT NULL DEFAULT '';
	`, nil); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return err
	}
	if _, err := s.exec(ctx, `
		ALTER TABLE location_candidate_interview_names
		ADD COLUMN priority INTEGER NOT NULL DEFAULT 100;
	`, nil); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return err
	}
	if _, err := s.exec(ctx, `
		UPDATE location_candidate_interview_names
		SET priority = id
		WHERE (COALESCE(priority, 0) <= 0 OR priority = 100)
			AND NOT EXISTS (
				SELECT 1 FROM location_candidate_interview_names AS x
				WHERE COALESCE(x.priority, 0) > 0 AND x.priority != 100
			);
	`, nil); err != nil {
		return err
	}
	if err := s.ensureLocationJobDepartmentMigration(ctx); err != nil {
		return err
	}
	if err := s.ensureCandidateInterviewQuestionResponseMigration(ctx); err != nil {
		return err
	}
	if err := s.ensureCandidateInterviewQuestionTypeMigration(ctx); err != nil {
		return err
	}
	if err := s.ensureCandidateInterviewQuestionAnswerSnapshotMigration(ctx); err != nil {
		return err
	}
	if err := s.ensureUniformOrderLineItemNumberMigration(ctx); err != nil {
		return err
	}
	if err := s.ensureDocumentTemplateDefaults(ctx); err != nil {
		return err
	}
	_, err := s.exec(ctx, `DELETE FROM sessions WHERE expires_at <= @now;`, map[string]string{
		"now": strconv.FormatInt(time.Now().UTC().Unix(), 10),
	})
	return err
}

func (s *sqliteStore) ensureLocationJobDepartmentMigration(ctx context.Context) error {
	hasColumn := func(tableName, columnName string) (bool, error) {
		rows, err := s.query(ctx, fmt.Sprintf(`PRAGMA table_info(%s);`, tableName), nil)
		if err != nil {
			return false, err
		}
		for _, row := range rows {
			name, nameErr := valueAsString(row["name"])
			if nameErr != nil {
				return false, nameErr
			}
			if strings.EqualFold(strings.TrimSpace(name), columnName) {
				return true, nil
			}
		}
		return false, nil
	}
	tableExists := func(tableName string) (bool, error) {
		rows, err := s.query(ctx, `
			SELECT 1
			FROM sqlite_master
			WHERE type = 'table' AND name = @name
			LIMIT 1;
		`, map[string]string{"name": tableName})
		if err != nil {
			return false, err
		}
		return len(rows) > 0, nil
	}

	legacyHasDepartment, err := hasColumn("location_jobs_legacy", "department_id")
	if err != nil {
		return err
	}
	currentHasDepartment, err := hasColumn("location_jobs", "department_id")
	if err != nil {
		return err
	}

	sourceTable := ""
	switch {
	case legacyHasDepartment:
		sourceTable = "location_jobs_legacy"
	case currentHasDepartment:
		if _, err := s.exec(ctx, `ALTER TABLE location_jobs RENAME TO location_jobs_legacy;`, nil); err != nil {
			legacyHasDepartment, legacyErr := hasColumn("location_jobs_legacy", "department_id")
			if legacyErr != nil {
				return legacyErr
			}
			if !legacyHasDepartment {
				return err
			}
		}
		sourceTable = "location_jobs_legacy"
	default:
		return nil
	}

	exists, err := tableExists(sourceTable)
	if err != nil {
		return err
	}
	if !exists {
		// Another process may have completed migration between checks.
		return nil
	}

	statements := []string{
		`CREATE TABLE IF NOT EXISTS location_jobs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			location_number TEXT NOT NULL,
			name TEXT NOT NULL,
			pay_type TEXT NOT NULL DEFAULT '',
			pay_amount_cents INTEGER NOT NULL DEFAULT 0,
			created_at INTEGER NOT NULL,
			UNIQUE(location_number, name),
			FOREIGN KEY(location_number) REFERENCES locations(number) ON DELETE CASCADE
		);`,
		`CREATE INDEX IF NOT EXISTS idx_location_jobs_location_name ON location_jobs(location_number, name ASC);`,
		`CREATE TABLE IF NOT EXISTS location_job_departments (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			location_number TEXT NOT NULL,
			job_id INTEGER NOT NULL,
			department_id INTEGER NOT NULL,
			created_at INTEGER NOT NULL,
			UNIQUE(location_number, job_id, department_id),
			FOREIGN KEY(location_number) REFERENCES locations(number) ON DELETE CASCADE,
			FOREIGN KEY(job_id) REFERENCES location_jobs(id) ON DELETE CASCADE,
			FOREIGN KEY(department_id) REFERENCES location_departments(id) ON DELETE CASCADE
		);`,
		`CREATE INDEX IF NOT EXISTS idx_location_job_departments_location_job ON location_job_departments(location_number, job_id, department_id);`,
		fmt.Sprintf(`INSERT INTO location_jobs (location_number, name, created_at)
		SELECT location_number, name, MIN(created_at)
		FROM %s
		GROUP BY location_number, name;`, sourceTable),
		fmt.Sprintf(`INSERT OR IGNORE INTO location_job_departments (location_number, job_id, department_id, created_at)
		SELECT l.location_number, j.id, l.department_id, l.created_at
		FROM %s l
		INNER JOIN location_jobs j
			ON j.location_number = l.location_number
			AND j.name = l.name
		WHERE l.department_id > 0;`, sourceTable),
		fmt.Sprintf(`UPDATE location_employees
		SET job_id = COALESCE((
			SELECT j.id
			FROM %s l
			INNER JOIN location_jobs j
				ON j.location_number = l.location_number
				AND j.name = l.name
			WHERE l.id = location_employees.job_id
			LIMIT 1
		), 0);`, sourceTable),
		fmt.Sprintf(`UPDATE archived_location_employees
		SET job_id = COALESCE((
			SELECT j.id
			FROM %s l
			INNER JOIN location_jobs j
				ON j.location_number = l.location_number
				AND j.name = l.name
			WHERE l.id = archived_location_employees.job_id
			LIMIT 1
		), 0);`, sourceTable),
	}
	if sourceTable == "location_jobs_legacy" {
		statements = append(statements, `DROP TABLE IF EXISTS location_jobs_legacy;`)
	}
	for _, stmt := range statements {
		if _, err := s.exec(ctx, stmt, nil); err != nil {
			return err
		}
	}
	return nil
}

func (s *sqliteStore) ensureCandidateInterviewQuestionResponseMigration(ctx context.Context) error {
	rows, err := s.query(ctx, `PRAGMA table_info(location_candidate_interview_questions);`, nil)
	if err != nil {
		return err
	}
	hasResponseType := false
	hasResponseOptions := false
	for _, row := range rows {
		name, nameErr := valueAsString(row["name"])
		if nameErr != nil {
			return nameErr
		}
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "response_type":
			hasResponseType = true
		case "response_options":
			hasResponseOptions = true
		}
	}
	if !hasResponseType {
		if _, err := s.exec(ctx, `
			ALTER TABLE location_candidate_interview_questions
			ADD COLUMN response_type TEXT NOT NULL DEFAULT 'text';
		`, nil); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
			return err
		}
	}
	if !hasResponseOptions {
		if _, err := s.exec(ctx, `
			ALTER TABLE location_candidate_interview_questions
			ADD COLUMN response_options TEXT NOT NULL DEFAULT '';
		`, nil); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
			return err
		}
	}
	_, err = s.exec(ctx, `
		UPDATE location_candidate_interview_questions
		SET response_type = 'text'
		WHERE LOWER(TRIM(COALESCE(response_type, ''))) NOT IN ('text', 'multiple_choice', 'number');
	`, nil)
	return err
}

func (s *sqliteStore) ensureCandidateInterviewQuestionTypeMigration(ctx context.Context) error {
	rows, err := s.query(ctx, `PRAGMA table_info(location_candidate_interview_questions);`, nil)
	if err != nil {
		return err
	}
	needsMigration := false
	for _, row := range rows {
		name, nameErr := valueAsString(row["name"])
		if nameErr != nil {
			return nameErr
		}
		if strings.EqualFold(strings.TrimSpace(name), "interview_name_id") {
			notNull, parseErr := valueAsInt64(row["notnull"])
			if parseErr != nil {
				return parseErr
			}
			needsMigration = notNull == 1
			break
		}
	}
	if !needsMigration {
		return nil
	}
	statements := []string{
		`CREATE TABLE IF NOT EXISTS location_candidate_interview_questions_new (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			location_number TEXT NOT NULL,
			interview_name_id INTEGER,
			question TEXT NOT NULL,
			response_type TEXT NOT NULL DEFAULT 'text',
			response_options TEXT NOT NULL DEFAULT '',
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL,
			FOREIGN KEY(location_number) REFERENCES locations(number) ON DELETE CASCADE,
			FOREIGN KEY(interview_name_id) REFERENCES location_candidate_interview_names(id) ON DELETE CASCADE
		);`,
		`INSERT INTO location_candidate_interview_questions_new (id, location_number, interview_name_id, question, response_type, response_options, created_at, updated_at)
		SELECT id, location_number, interview_name_id, question, response_type, response_options, created_at, updated_at
		FROM location_candidate_interview_questions;`,
		`DROP TABLE location_candidate_interview_questions;`,
		`ALTER TABLE location_candidate_interview_questions_new RENAME TO location_candidate_interview_questions;`,
		`CREATE INDEX IF NOT EXISTS idx_candidate_interview_questions_location_name ON location_candidate_interview_questions(location_number, interview_name_id, id ASC);`,
	}
	for _, stmt := range statements {
		if _, err := s.exec(ctx, stmt, nil); err != nil {
			return err
		}
	}
	backfillStatements := []string{
		`CREATE TABLE IF NOT EXISTS location_candidate_interview_question_types (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			question_id INTEGER NOT NULL,
			interview_name_id INTEGER NOT NULL,
			created_at INTEGER NOT NULL,
			UNIQUE(question_id, interview_name_id),
			FOREIGN KEY(question_id) REFERENCES location_candidate_interview_questions(id) ON DELETE CASCADE,
			FOREIGN KEY(interview_name_id) REFERENCES location_candidate_interview_names(id) ON DELETE CASCADE
		);`,
		`CREATE INDEX IF NOT EXISTS idx_candidate_interview_question_types_question ON location_candidate_interview_question_types(question_id, interview_name_id ASC);`,
		`CREATE INDEX IF NOT EXISTS idx_candidate_interview_question_types_name ON location_candidate_interview_question_types(interview_name_id, question_id ASC);`,
		`INSERT OR IGNORE INTO location_candidate_interview_question_types (question_id, interview_name_id, created_at)
		SELECT id, interview_name_id, COALESCE(updated_at, created_at)
		FROM location_candidate_interview_questions
		WHERE interview_name_id IS NOT NULL AND interview_name_id > 0;`,
	}
	for _, stmt := range backfillStatements {
		if _, err := s.exec(ctx, stmt, nil); err != nil {
			return err
		}
	}
	return nil
}

func (s *sqliteStore) ensureCandidateInterviewQuestionAnswerSnapshotMigration(ctx context.Context) error {
	columnRows, err := s.query(ctx, `PRAGMA table_info(location_candidate_interview_question_answers);`, nil)
	if err != nil {
		return err
	}
	hasSnapshotColumn := false
	for _, row := range columnRows {
		name, nameErr := valueAsString(row["name"])
		if nameErr != nil {
			return nameErr
		}
		if strings.EqualFold(strings.TrimSpace(name), "question_text_snapshot") {
			hasSnapshotColumn = true
			break
		}
	}
	fkRows, err := s.query(ctx, `PRAGMA foreign_key_list(location_candidate_interview_question_answers);`, nil)
	if err != nil {
		return err
	}
	hasQuestionForeignKey := false
	for _, row := range fkRows {
		refTable, refErr := valueAsString(row["table"])
		if refErr != nil {
			return refErr
		}
		if strings.EqualFold(strings.TrimSpace(refTable), "location_candidate_interview_questions") {
			hasQuestionForeignKey = true
			break
		}
	}
	if !hasQuestionForeignKey {
		if hasSnapshotColumn {
			return nil
		}
		_, err := s.exec(ctx, `
			ALTER TABLE location_candidate_interview_question_answers
			ADD COLUMN question_text_snapshot TEXT NOT NULL DEFAULT '';
		`, nil)
		return err
	}
	insertQuery := `
		INSERT INTO location_candidate_interview_question_answers_new (id, interview_id, question_id, question_text_snapshot, answer, created_at)
		SELECT a.id, a.interview_id, a.question_id, COALESCE(NULLIF(TRIM(q.question), ''), ''), a.answer, a.created_at
		FROM location_candidate_interview_question_answers a
		LEFT JOIN location_candidate_interview_questions q ON q.id = a.question_id;
	`
	if hasSnapshotColumn {
		insertQuery = `
			INSERT INTO location_candidate_interview_question_answers_new (id, interview_id, question_id, question_text_snapshot, answer, created_at)
			SELECT a.id, a.interview_id, a.question_id,
				COALESCE(NULLIF(TRIM(a.question_text_snapshot), ''), COALESCE(NULLIF(TRIM(q.question), ''), '')),
				a.answer, a.created_at
			FROM location_candidate_interview_question_answers a
			LEFT JOIN location_candidate_interview_questions q ON q.id = a.question_id;
		`
	}
	statements := []string{
		`CREATE TABLE IF NOT EXISTS location_candidate_interview_question_answers_new (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			interview_id INTEGER NOT NULL,
			question_id INTEGER NOT NULL,
			question_text_snapshot TEXT NOT NULL DEFAULT '',
			answer TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			UNIQUE(interview_id, question_id),
			FOREIGN KEY(interview_id) REFERENCES location_candidate_interviews(id) ON DELETE CASCADE
		);`,
		insertQuery,
		`DROP TABLE location_candidate_interview_question_answers;`,
		`ALTER TABLE location_candidate_interview_question_answers_new RENAME TO location_candidate_interview_question_answers;`,
		`CREATE INDEX IF NOT EXISTS idx_candidate_interview_question_answers_interview ON location_candidate_interview_question_answers(interview_id, id ASC);`,
	}
	for _, stmt := range statements {
		if _, err := s.exec(ctx, stmt, nil); err != nil {
			return err
		}
	}
	return nil
}

func (s *sqliteStore) ensureUniformOrderLineItemNumberMigration(ctx context.Context) error {
	rows, err := s.query(ctx, `PRAGMA table_info(location_uniform_order_lines);`, nil)
	if err != nil {
		return err
	}
	hasItemNumber := false
	for _, row := range rows {
		name, nameErr := valueAsString(row["name"])
		if nameErr != nil {
			return nameErr
		}
		if strings.EqualFold(strings.TrimSpace(name), "item_number") {
			hasItemNumber = true
			break
		}
	}
	if hasItemNumber {
		return nil
	}
	_, err = s.exec(ctx, `
		ALTER TABLE location_uniform_order_lines
		ADD COLUMN item_number TEXT NOT NULL DEFAULT '';
	`, nil)
	return err
}

func (s *sqliteStore) ensureDocumentTemplateDefaults(ctx context.Context) error {
	now := strconv.FormatInt(time.Now().UTC().Unix(), 10)
	defaults := []documentTemplate{
		{
			DocumentType:      "i9",
			TemplatePath:      "docs/i9.pdf",
			SignaturePage:     i9EmployeeSignaturePlacement.Page,
			SignatureTopLeftX: i9EmployeeSignaturePlacement.TopLeftX,
			SignatureTopLeftY: i9EmployeeSignaturePlacement.TopLeftY,
			SignatureWidth:    i9EmployeeSignaturePlacement.BottomRightX - i9EmployeeSignaturePlacement.TopLeftX,
			SignatureHeight:   i9EmployeeSignaturePlacement.BottomRightY - i9EmployeeSignaturePlacement.TopLeftY,
			SignatureZoom:     260,
			FormFieldName:     i9EmployeeSignaturePlacement.FormFieldName,
		},
		{
			DocumentType:      "w4",
			TemplatePath:      "docs/w4.pdf",
			SignaturePage:     w4EmployeeSignaturePlacement.Page,
			SignatureTopLeftX: w4EmployeeSignaturePlacement.TopLeftX,
			SignatureTopLeftY: w4EmployeeSignaturePlacement.TopLeftY,
			SignatureWidth:    w4EmployeeSignaturePlacement.BottomRightX - w4EmployeeSignaturePlacement.TopLeftX,
			SignatureHeight:   w4EmployeeSignaturePlacement.BottomRightY - w4EmployeeSignaturePlacement.TopLeftY,
			SignatureZoom:     260,
			FormFieldName:     w4EmployeeSignaturePlacement.FormFieldName,
		},
	}
	for _, tmpl := range defaults {
		_, err := s.exec(ctx, `
			INSERT INTO document_templates (
				document_type, template_path, signature_page, signature_top_left_x, signature_top_left_y,
				signature_width, signature_height, signature_zoom, form_field_name, created_at, updated_at
			)
			VALUES (
				@document_type, @template_path, @signature_page, @signature_top_left_x, @signature_top_left_y,
				@signature_width, @signature_height, @signature_zoom, @form_field_name, @created_at, @updated_at
			)
			ON CONFLICT(document_type)
			DO UPDATE SET
				template_path = excluded.template_path,
				signature_page = excluded.signature_page,
				signature_top_left_x = excluded.signature_top_left_x,
				signature_top_left_y = excluded.signature_top_left_y,
				signature_width = excluded.signature_width,
				signature_height = excluded.signature_height,
				signature_zoom = excluded.signature_zoom,
				form_field_name = excluded.form_field_name,
				updated_at = excluded.updated_at;
		`, map[string]string{
			"document_type":        tmpl.DocumentType,
			"template_path":        tmpl.TemplatePath,
			"signature_page":       strconv.Itoa(tmpl.SignaturePage),
			"signature_top_left_x": strconv.FormatFloat(tmpl.SignatureTopLeftX, 'f', 2, 64),
			"signature_top_left_y": strconv.FormatFloat(tmpl.SignatureTopLeftY, 'f', 2, 64),
			"signature_width":      strconv.FormatFloat(tmpl.SignatureWidth, 'f', 2, 64),
			"signature_height":     strconv.FormatFloat(tmpl.SignatureHeight, 'f', 2, 64),
			"signature_zoom":       strconv.Itoa(tmpl.SignatureZoom),
			"form_field_name":      tmpl.FormFieldName,
			"created_at":           now,
			"updated_at":           now,
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *sqliteStore) ensureAdminUser(ctx context.Context, username, password string) error {
	hash, err := security.HashPassword(password)
	if err != nil {
		return err
	}

	_, err = s.exec(ctx, `
		INSERT INTO users (username, password_hash, is_admin, role, access_level, location_number, time_punch_name, created_at)
		VALUES (@username, @password_hash, 1, @role, @access_level, '', '', @created_at)
		ON CONFLICT(username)
		DO UPDATE SET password_hash = excluded.password_hash, is_admin = 1, role = excluded.role, access_level = excluded.access_level, location_number = '', time_punch_name = '';
	`, map[string]string{
		"username":      username,
		"password_hash": hash,
		"role":          userRoleAdmin,
		"access_level":  teamAccessLevelNoAccess,
		"created_at":    strconv.FormatInt(time.Now().UTC().Unix(), 10),
	})
	return err
}

func (s *sqliteStore) ensureDefaultDepartmentsAndJobsForAllLocations(ctx context.Context) error {
	locations, err := s.listLocations(ctx)
	if err != nil {
		return err
	}
	for _, loc := range locations {
		if err := s.ensureDefaultDepartmentsAndJobs(ctx, loc.Number); err != nil {
			return err
		}
	}
	return nil
}

func (s *sqliteStore) ensureDefaultDepartmentsAndJobs(ctx context.Context, locationNumber string) error {
	if strings.TrimSpace(locationNumber) == "" {
		return errors.New("location number is required")
	}
	now := strconv.FormatInt(time.Now().UTC().Unix(), 10)
	for _, departmentName := range defaultLocationDepartments {
		_, err := s.exec(ctx, `
			INSERT OR IGNORE INTO location_departments (location_number, name, created_at)
			VALUES (@location_number, @name, @created_at);
		`, map[string]string{
			"location_number": locationNumber,
			"name":            strings.TrimSpace(departmentName),
			"created_at":      now,
		})
		if err != nil {
			return err
		}
	}
	for _, payBand := range defaultLocationPayBands {
		_, err := s.exec(ctx, `
			INSERT OR IGNORE INTO location_jobs (location_number, name, pay_type, pay_amount_cents, created_at)
			VALUES (@location_number, @name, @pay_type, @pay_amount_cents, @created_at);
		`, map[string]string{
			"location_number":  locationNumber,
			"name":             strings.TrimSpace(payBand.Name),
			"pay_type":         strings.ToLower(strings.TrimSpace(payBand.PayType)),
			"pay_amount_cents": strconv.FormatInt(payBand.PayAmountCents, 10),
			"created_at":       now,
		})
		if err != nil {
			return err
		}
	}
	_, err := s.exec(ctx, `
		UPDATE location_jobs
		SET pay_type = CASE
				WHEN LOWER(TRIM(COALESCE(pay_type, ''))) IN ('hourly', 'salary') THEN LOWER(TRIM(pay_type))
				ELSE 'hourly'
			END,
			pay_amount_cents = CASE
				WHEN pay_amount_cents > 0 THEN pay_amount_cents
				ELSE 1200
			END
		WHERE location_number = @location_number;
	`, map[string]string{
		"location_number": locationNumber,
	})
	if err != nil {
		return err
	}
	return nil
}

func (s *sqliteStore) createLocation(ctx context.Context, loc location) error {
	_, err := s.exec(ctx, `
		INSERT INTO locations (number, name, email, phone, created_at)
		VALUES (@number, @name, @email, @phone, @created_at);
	`, map[string]string{
		"number":     loc.Number,
		"name":       loc.Name,
		"email":      strings.TrimSpace(loc.Email),
		"phone":      strings.TrimSpace(loc.Phone),
		"created_at": strconv.FormatInt(loc.CreatedAt.UTC().Unix(), 10),
	})
	return err
}

func (s *sqliteStore) updateLocationName(ctx context.Context, number, name string) error {
	_, err := s.exec(ctx, `
		UPDATE locations
		SET name = @name
		WHERE number = @number;
	`, map[string]string{
		"name":   name,
		"number": number,
	})
	return err
}

func (s *sqliteStore) deleteLocation(ctx context.Context, number string) error {
	if _, err := s.getLocationByNumber(ctx, number); err != nil {
		return err
	}
	statement := `
		BEGIN;
		DELETE FROM employee_photo_tokens
		WHERE location_number = @number;
		DELETE FROM employee_paperwork_tokens
		WHERE location_number = @number;
		DELETE FROM employee_i9_documents
		WHERE location_number = @number;
		DELETE FROM employee_i9_forms
		WHERE location_number = @number;
		DELETE FROM employee_w4_forms
		WHERE location_number = @number;
		DELETE FROM location_time_punch_entries
		WHERE location_number = @number;
		DELETE FROM location_time_punch_tokens
		WHERE location_number = @number;
		DELETE FROM location_time_off_requests
		WHERE location_number = @number;
		DELETE FROM location_time_off_tokens
		WHERE location_number = @number;
		DELETE FROM location_business_days
		WHERE location_number = @number;
		DELETE FROM location_candidate_interview_grades
		WHERE interview_id IN (
			SELECT id
			FROM location_candidate_interviews
			WHERE location_number = @number
		);
		DELETE FROM location_candidate_interview_question_answers
		WHERE interview_id IN (
			SELECT id
			FROM location_candidate_interviews
			WHERE location_number = @number
		);
		DELETE FROM location_candidate_interviews
		WHERE location_number = @number;
		DELETE FROM location_candidates
		WHERE location_number = @number;
		DELETE FROM location_candidate_interview_question_types
		WHERE question_id IN (
			SELECT id
			FROM location_candidate_interview_questions
			WHERE location_number = @number
		);
		DELETE FROM location_candidate_interview_questions
		WHERE location_number = @number;
		DELETE FROM location_candidate_values
		WHERE location_number = @number;
		DELETE FROM location_candidate_interview_names
		WHERE location_number = @number;
		DELETE FROM location_candidate_interview_tokens
		WHERE location_number = @number;
		DELETE FROM location_uniform_order_tokens
		WHERE location_number = @number;
		DELETE FROM location_uniform_order_lines
		WHERE order_id IN (
			SELECT id
			FROM location_uniform_orders
			WHERE location_number = @number
		);
		DELETE FROM location_uniform_orders
		WHERE location_number = @number;
		DELETE FROM location_uniform_item_images
		WHERE item_id IN (
			SELECT id
			FROM location_uniform_items
			WHERE location_number = @number
		);
		DELETE FROM location_uniform_item_sizes
		WHERE item_id IN (
			SELECT id
			FROM location_uniform_items
			WHERE location_number = @number
		);
		DELETE FROM location_uniform_item_size_options
		WHERE item_id IN (
			SELECT id
			FROM location_uniform_items
			WHERE location_number = @number
		);
		DELETE FROM location_uniform_items
		WHERE location_number = @number;
		DELETE FROM archived_employee_i9_documents
		WHERE archived_employee_id IN (
			SELECT id
			FROM archived_location_employees
			WHERE location_number = @number
		);
		DELETE FROM archived_employee_i9_forms
		WHERE archived_employee_id IN (
			SELECT id
			FROM archived_location_employees
			WHERE location_number = @number
		);
		DELETE FROM archived_employee_w4_forms
		WHERE archived_employee_id IN (
			SELECT id
			FROM archived_location_employees
			WHERE location_number = @number
		);
		DELETE FROM archived_location_employees
		WHERE location_number = @number;
		DELETE FROM location_employees
		WHERE location_number = @number;
		DELETE FROM users
		WHERE location_number = @number;
		DELETE FROM locations
		WHERE number = @number;
		COMMIT;
	`
	_, err := s.exec(ctx, statement, map[string]string{"number": number})
	return err
}

func (s *sqliteStore) listLocations(ctx context.Context) ([]location, error) {
	rows, err := s.query(ctx, `
		SELECT name, number, email, phone, created_at
		FROM locations
		ORDER BY created_at ASC;
	`, nil)
	if err != nil {
		return nil, err
	}

	out := make([]location, 0, len(rows))
	for _, row := range rows {
		name, err := valueAsString(row["name"])
		if err != nil {
			return nil, err
		}
		number, err := valueAsString(row["number"])
		if err != nil {
			return nil, err
		}
		email, err := valueAsString(row["email"])
		if err != nil {
			return nil, err
		}
		phone, err := valueAsString(row["phone"])
		if err != nil {
			return nil, err
		}
		createdAtUnix, err := valueAsInt64(row["created_at"])
		if err != nil {
			return nil, err
		}
		out = append(out, location{
			Name:      name,
			Number:    number,
			Email:     email,
			Phone:     phone,
			CreatedAt: time.Unix(createdAtUnix, 0).UTC(),
		})
	}
	return out, nil
}

func (s *sqliteStore) getLocationByNumber(ctx context.Context, number string) (*location, error) {
	rows, err := s.query(ctx, `
		SELECT name, number, email, phone, created_at
		FROM locations
		WHERE number = @number
		LIMIT 1;
	`, map[string]string{"number": number})
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, errNotFound
	}
	name, err := valueAsString(rows[0]["name"])
	if err != nil {
		return nil, err
	}
	locNumber, err := valueAsString(rows[0]["number"])
	if err != nil {
		return nil, err
	}
	email, err := valueAsString(rows[0]["email"])
	if err != nil {
		return nil, err
	}
	phone, err := valueAsString(rows[0]["phone"])
	if err != nil {
		return nil, err
	}
	createdAtUnix, err := valueAsInt64(rows[0]["created_at"])
	if err != nil {
		return nil, err
	}
	return &location{
		Name:      name,
		Number:    locNumber,
		Email:     email,
		Phone:     phone,
		CreatedAt: time.Unix(createdAtUnix, 0).UTC(),
	}, nil
}

func (s *sqliteStore) getLocationSettings(ctx context.Context, number string) (*locationSettings, error) {
	rows, err := s.query(ctx, `
		SELECT location_number, employer_rep_signature, w4_employer_name, w4_employer_street, w4_employer_city, w4_employer_state, w4_employer_ein, w4_employer_address, departments_csv, restaurant_username
		FROM location_settings
		WHERE location_number = @location_number
		LIMIT 1;
	`, map[string]string{"location_number": number})
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return &locationSettings{
			LocationNumber:       number,
			EmployerRepSignature: "",
			BusinessName:         "",
			BusinessStreet:       "",
			BusinessCity:         "",
			BusinessState:        "",
			BusinessEIN:          "",
			BusinessAddress:      "",
			W4EmployerName:       "",
			W4EmployerStreet:     "",
			W4EmployerCity:       "",
			W4EmployerState:      "",
			W4EmployerEIN:        "",
			W4EmployerAddress:    "",
			Departments:          []string{"INIT"},
			RestaurantUsername:   "",
		}, nil
	}
	locationNumber, err := valueAsString(rows[0]["location_number"])
	if err != nil {
		return nil, err
	}
	employerRepSignature, err := valueAsString(rows[0]["employer_rep_signature"])
	if err != nil {
		return nil, err
	}
	w4EmployerName, err := valueAsString(rows[0]["w4_employer_name"])
	if err != nil {
		return nil, err
	}
	w4EmployerStreet, err := valueAsString(rows[0]["w4_employer_street"])
	if err != nil {
		return nil, err
	}
	w4EmployerCity, err := valueAsString(rows[0]["w4_employer_city"])
	if err != nil {
		return nil, err
	}
	w4EmployerState, err := valueAsString(rows[0]["w4_employer_state"])
	if err != nil {
		return nil, err
	}
	w4EmployerEIN, err := valueAsString(rows[0]["w4_employer_ein"])
	if err != nil {
		return nil, err
	}
	w4EmployerAddress, err := valueAsString(rows[0]["w4_employer_address"])
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(w4EmployerStreet) == "" && strings.TrimSpace(w4EmployerCity) == "" && strings.TrimSpace(w4EmployerState) == "" {
		w4EmployerStreet, w4EmployerCity, w4EmployerState = splitBusinessAddressParts(w4EmployerAddress)
	}
	departmentsCSV, err := valueAsString(rows[0]["departments_csv"])
	if err != nil {
		return nil, err
	}
	restaurantUsername, err := valueAsString(rows[0]["restaurant_username"])
	if err != nil {
		return nil, err
	}
	businessAddress := composeBusinessAddress(w4EmployerStreet, w4EmployerCity, w4EmployerState)
	if businessAddress == "" {
		businessAddress = w4EmployerAddress
	}
	return &locationSettings{
		LocationNumber:       locationNumber,
		EmployerRepSignature: employerRepSignature,
		BusinessName:         w4EmployerName,
		BusinessStreet:       w4EmployerStreet,
		BusinessCity:         w4EmployerCity,
		BusinessState:        w4EmployerState,
		BusinessEIN:          w4EmployerEIN,
		BusinessAddress:      businessAddress,
		W4EmployerName:       w4EmployerName,
		W4EmployerStreet:     w4EmployerStreet,
		W4EmployerCity:       w4EmployerCity,
		W4EmployerState:      w4EmployerState,
		W4EmployerEIN:        w4EmployerEIN,
		W4EmployerAddress:    w4EmployerAddress,
		Departments:          parseDepartmentsCSV(departmentsCSV),
		RestaurantUsername:   strings.TrimSpace(restaurantUsername),
	}, nil
}

func (s *sqliteStore) upsertLocationSettings(ctx context.Context, settings locationSettings) error {
	now := time.Now().UTC().Unix()
	departments := sanitizeDepartments(settings.Departments)
	businessName := strings.TrimSpace(settings.BusinessName)
	if businessName == "" {
		businessName = strings.TrimSpace(settings.W4EmployerName)
	}
	businessStreet := strings.TrimSpace(settings.BusinessStreet)
	if businessStreet == "" {
		businessStreet = strings.TrimSpace(settings.W4EmployerStreet)
	}
	businessCity := strings.TrimSpace(settings.BusinessCity)
	if businessCity == "" {
		businessCity = strings.TrimSpace(settings.W4EmployerCity)
	}
	businessState := strings.TrimSpace(settings.BusinessState)
	if businessState == "" {
		businessState = strings.TrimSpace(settings.W4EmployerState)
	}
	businessEIN := strings.TrimSpace(settings.BusinessEIN)
	if businessEIN == "" {
		businessEIN = strings.TrimSpace(settings.W4EmployerEIN)
	}
	if businessStreet == "" && businessCity == "" && businessState == "" {
		businessStreet, businessCity, businessState = splitBusinessAddressParts(settings.BusinessAddress)
	}
	businessAddress := strings.TrimSpace(settings.BusinessAddress)
	composedAddress := composeBusinessAddress(businessStreet, businessCity, businessState)
	if composedAddress != "" {
		businessAddress = composedAddress
	}
	if businessAddress == "" {
		businessAddress = strings.TrimSpace(settings.W4EmployerAddress)
	}
	_, err := s.exec(ctx, `
		INSERT INTO location_settings (location_number, employer_rep_signature, w4_employer_name, w4_employer_street, w4_employer_city, w4_employer_state, w4_employer_ein, w4_employer_address, departments_csv, restaurant_username, updated_at, created_at)
		VALUES (@location_number, @employer_rep_signature, @w4_employer_name, @w4_employer_street, @w4_employer_city, @w4_employer_state, @w4_employer_ein, @w4_employer_address, @departments_csv, @restaurant_username, @updated_at, @created_at)
		ON CONFLICT(location_number)
		DO UPDATE SET
			employer_rep_signature = excluded.employer_rep_signature,
			w4_employer_name = excluded.w4_employer_name,
			w4_employer_street = excluded.w4_employer_street,
			w4_employer_city = excluded.w4_employer_city,
			w4_employer_state = excluded.w4_employer_state,
			w4_employer_ein = excluded.w4_employer_ein,
			w4_employer_address = excluded.w4_employer_address,
			departments_csv = excluded.departments_csv,
			restaurant_username = excluded.restaurant_username,
			updated_at = excluded.updated_at;
	`, map[string]string{
		"location_number":        settings.LocationNumber,
		"employer_rep_signature": settings.EmployerRepSignature,
		"w4_employer_name":       businessName,
		"w4_employer_street":     businessStreet,
		"w4_employer_city":       businessCity,
		"w4_employer_state":      businessState,
		"w4_employer_ein":        businessEIN,
		"w4_employer_address":    businessAddress,
		"departments_csv":        strings.Join(departments, ","),
		"restaurant_username":    strings.TrimSpace(settings.RestaurantUsername),
		"updated_at":             strconv.FormatInt(now, 10),
		"created_at":             strconv.FormatInt(now, 10),
	})
	return err
}

func (s *sqliteStore) listCandidateValues(ctx context.Context, locationNumber string) ([]candidateValue, error) {
	rows, err := s.query(ctx, `
		SELECT id, location_number, name, description, created_at, updated_at
		FROM location_candidate_values
		WHERE location_number = @location_number
		ORDER BY id ASC;
	`, map[string]string{"location_number": locationNumber})
	if err != nil {
		return nil, err
	}
	values := make([]candidateValue, 0, len(rows))
	for _, row := range rows {
		id, err := valueAsInt64(row["id"])
		if err != nil {
			return nil, err
		}
		loc, err := valueAsString(row["location_number"])
		if err != nil {
			return nil, err
		}
		name, err := valueAsString(row["name"])
		if err != nil {
			return nil, err
		}
		description, err := valueAsString(row["description"])
		if err != nil {
			return nil, err
		}
		createdAtUnix, err := valueAsInt64(row["created_at"])
		if err != nil {
			return nil, err
		}
		updatedAtUnix, err := valueAsInt64(row["updated_at"])
		if err != nil {
			return nil, err
		}
		values = append(values, candidateValue{
			ID:             id,
			LocationNumber: loc,
			Name:           name,
			Description:    description,
			CreatedAt:      time.Unix(createdAtUnix, 0).UTC(),
			UpdatedAt:      time.Unix(updatedAtUnix, 0).UTC(),
		})
	}
	return values, nil
}

func (s *sqliteStore) createCandidateValue(ctx context.Context, value candidateValue) (int64, error) {
	now := time.Now().UTC().Unix()
	_, err := s.exec(ctx, `
		INSERT INTO location_candidate_values (location_number, name, description, created_at, updated_at)
		VALUES (@location_number, @name, @description, @created_at, @updated_at);
	`, map[string]string{
		"location_number": value.LocationNumber,
		"name":            value.Name,
		"description":     value.Description,
		"created_at":      strconv.FormatInt(now, 10),
		"updated_at":      strconv.FormatInt(now, 10),
	})
	if err != nil {
		return 0, err
	}
	rows, err := s.query(ctx, `
		SELECT id
		FROM location_candidate_values
		WHERE location_number = @location_number AND name = @name
		ORDER BY id DESC
		LIMIT 1;
	`, map[string]string{
		"location_number": value.LocationNumber,
		"name":            value.Name,
	})
	if err != nil {
		return 0, err
	}
	if len(rows) == 0 {
		return 0, errNotFound
	}
	return valueAsInt64(rows[0]["id"])
}

func (s *sqliteStore) updateCandidateValue(ctx context.Context, locationNumber string, valueID int64, name, description string) error {
	now := time.Now().UTC().Unix()
	_, err := s.exec(ctx, `
		UPDATE location_candidate_values
		SET name = @name, description = @description, updated_at = @updated_at
		WHERE id = @id AND location_number = @location_number;
	`, map[string]string{
		"id":              strconv.FormatInt(valueID, 10),
		"location_number": locationNumber,
		"name":            name,
		"description":     description,
		"updated_at":      strconv.FormatInt(now, 10),
	})
	if err != nil {
		return err
	}
	rows, err := s.query(ctx, `
		SELECT COUNT(*) AS count
		FROM location_candidate_values
		WHERE id = @id AND location_number = @location_number;
	`, map[string]string{
		"id":              strconv.FormatInt(valueID, 10),
		"location_number": locationNumber,
	})
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		return errNotFound
	}
	count, err := valueAsInt64(rows[0]["count"])
	if err != nil {
		return err
	}
	if count == 0 {
		return errNotFound
	}
	return nil
}

func (s *sqliteStore) deleteCandidateValue(ctx context.Context, locationNumber string, valueID int64) error {
	rows, err := s.query(ctx, `
		SELECT COUNT(*) AS count
		FROM location_candidate_values
		WHERE id = @id AND location_number = @location_number;
	`, map[string]string{
		"id":              strconv.FormatInt(valueID, 10),
		"location_number": locationNumber,
	})
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		return errNotFound
	}
	count, err := valueAsInt64(rows[0]["count"])
	if err != nil {
		return err
	}
	if count == 0 {
		return errNotFound
	}
	_, err = s.exec(ctx, `
		DELETE FROM location_candidate_values
		WHERE id = @id AND location_number = @location_number;
	`, map[string]string{
		"id":              strconv.FormatInt(valueID, 10),
		"location_number": locationNumber,
	})
	return err
}

func (s *sqliteStore) listCandidateInterviewNames(ctx context.Context, locationNumber string) ([]candidateInterviewName, error) {
	rows, err := s.query(ctx, `
		SELECT id, location_number, name, priority, created_at, updated_at
		FROM location_candidate_interview_names
		WHERE location_number = @location_number
		ORDER BY priority ASC, id ASC;
	`, map[string]string{"location_number": locationNumber})
	if err != nil {
		return nil, err
	}
	out := make([]candidateInterviewName, 0, len(rows))
	for _, row := range rows {
		id, err := valueAsInt64(row["id"])
		if err != nil {
			return nil, err
		}
		loc, err := valueAsString(row["location_number"])
		if err != nil {
			return nil, err
		}
		name, err := valueAsString(row["name"])
		if err != nil {
			return nil, err
		}
		priority, err := valueAsInt64(row["priority"])
		if err != nil {
			return nil, err
		}
		createdAtUnix, err := valueAsInt64(row["created_at"])
		if err != nil {
			return nil, err
		}
		updatedAtUnix, err := valueAsInt64(row["updated_at"])
		if err != nil {
			return nil, err
		}
		out = append(out, candidateInterviewName{
			ID:             id,
			LocationNumber: loc,
			Name:           name,
			Priority:       priority,
			CreatedAt:      time.Unix(createdAtUnix, 0).UTC(),
			UpdatedAt:      time.Unix(updatedAtUnix, 0).UTC(),
		})
	}
	return out, nil
}

func (s *sqliteStore) createCandidateInterviewName(ctx context.Context, name candidateInterviewName) (int64, error) {
	now := time.Now().UTC().Unix()
	_, err := s.exec(ctx, `
		INSERT INTO location_candidate_interview_names (location_number, name, priority, created_at, updated_at)
		VALUES (@location_number, @name, @priority, @created_at, @updated_at);
	`, map[string]string{
		"location_number": name.LocationNumber,
		"name":            strings.TrimSpace(name.Name),
		"priority":        strconv.FormatInt(name.Priority, 10),
		"created_at":      strconv.FormatInt(now, 10),
		"updated_at":      strconv.FormatInt(now, 10),
	})
	if err != nil {
		return 0, err
	}
	rows, err := s.query(ctx, `
		SELECT id
		FROM location_candidate_interview_names
		WHERE location_number = @location_number
		ORDER BY id DESC
		LIMIT 1;
	`, map[string]string{"location_number": name.LocationNumber})
	if err != nil {
		return 0, err
	}
	if len(rows) == 0 {
		return 0, errNotFound
	}
	return valueAsInt64(rows[0]["id"])
}

func (s *sqliteStore) updateCandidateInterviewNamePriority(ctx context.Context, locationNumber string, nameID, priority int64) error {
	rows, err := s.query(ctx, `
		SELECT COUNT(*) AS count
		FROM location_candidate_interview_names
		WHERE id = @id AND location_number = @location_number;
	`, map[string]string{
		"id":              strconv.FormatInt(nameID, 10),
		"location_number": locationNumber,
	})
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		return errNotFound
	}
	count, err := valueAsInt64(rows[0]["count"])
	if err != nil {
		return err
	}
	if count == 0 {
		return errNotFound
	}
	_, err = s.exec(ctx, `
		UPDATE location_candidate_interview_names
		SET priority = @priority, updated_at = @updated_at
		WHERE id = @id AND location_number = @location_number;
	`, map[string]string{
		"id":              strconv.FormatInt(nameID, 10),
		"location_number": locationNumber,
		"priority":        strconv.FormatInt(priority, 10),
		"updated_at":      strconv.FormatInt(time.Now().UTC().Unix(), 10),
	})
	return err
}

func (s *sqliteStore) deleteCandidateInterviewName(ctx context.Context, locationNumber string, nameID int64) error {
	rows, err := s.query(ctx, `
		SELECT COUNT(*) AS count
		FROM location_candidate_interview_names
		WHERE id = @id AND location_number = @location_number;
	`, map[string]string{
		"id":              strconv.FormatInt(nameID, 10),
		"location_number": locationNumber,
	})
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		return errNotFound
	}
	count, err := valueAsInt64(rows[0]["count"])
	if err != nil {
		return err
	}
	if count == 0 {
		return errNotFound
	}
	_, err = s.exec(ctx, `
		DELETE FROM location_candidate_interview_names
		WHERE id = @id AND location_number = @location_number;
	`, map[string]string{
		"id":              strconv.FormatInt(nameID, 10),
		"location_number": locationNumber,
	})
	return err
}

func (s *sqliteStore) listCandidateInterviewQuestions(ctx context.Context, locationNumber string, interviewNameID int64) ([]candidateInterviewQuestion, error) {
	query := `
		SELECT q.id, q.location_number, q.question, q.response_type, q.response_options, q.created_at, q.updated_at
		FROM location_candidate_interview_questions q
		WHERE q.location_number = @location_number
	`
	params := map[string]string{"location_number": locationNumber}
	if interviewNameID > 0 {
		query = `
			SELECT DISTINCT q.id, q.location_number, q.question, q.response_type, q.response_options, q.created_at, q.updated_at
			FROM location_candidate_interview_questions q
			INNER JOIN location_candidate_interview_question_types m ON m.question_id = q.id
			INNER JOIN location_candidate_interview_names n ON n.id = m.interview_name_id
			WHERE q.location_number = @location_number
			  AND n.location_number = @location_number
			  AND m.interview_name_id = @interview_name_id
		`
		params["interview_name_id"] = strconv.FormatInt(interviewNameID, 10)
	}
	query += " ORDER BY q.id ASC;"
	rows, err := s.query(ctx, query, params)
	if err != nil {
		return nil, err
	}
	out := make([]candidateInterviewQuestion, 0, len(rows))
	indexByID := make(map[int64]int, len(rows))
	for _, row := range rows {
		id, err := valueAsInt64(row["id"])
		if err != nil {
			return nil, err
		}
		loc, err := valueAsString(row["location_number"])
		if err != nil {
			return nil, err
		}
		question, err := valueAsString(row["question"])
		if err != nil {
			return nil, err
		}
		responseType, err := valueAsString(row["response_type"])
		if err != nil {
			return nil, err
		}
		responseOptionsRaw, err := valueAsString(row["response_options"])
		if err != nil {
			return nil, err
		}
		createdAtUnix, err := valueAsInt64(row["created_at"])
		if err != nil {
			return nil, err
		}
		updatedAtUnix, err := valueAsInt64(row["updated_at"])
		if err != nil {
			return nil, err
		}
		indexByID[id] = len(out)
		out = append(out, candidateInterviewQuestion{
			ID:              id,
			LocationNumber:  loc,
			Question:        question,
			ResponseType:    normalizeQuestionResponseType(responseType),
			ResponseOptions: parseQuestionResponseOptions(responseOptionsRaw),
			CreatedAt:       time.Unix(createdAtUnix, 0).UTC(),
			UpdatedAt:       time.Unix(updatedAtUnix, 0).UTC(),
		})
	}
	if len(out) == 0 {
		return out, nil
	}
	typeRows, err := s.query(ctx, `
		SELECT m.question_id, m.interview_name_id, n.name
		FROM location_candidate_interview_question_types m
		INNER JOIN location_candidate_interview_names n ON n.id = m.interview_name_id
		WHERE n.location_number = @location_number
		ORDER BY m.question_id ASC, m.interview_name_id ASC;
	`, map[string]string{
		"location_number": locationNumber,
	})
	if err != nil {
		return nil, err
	}
	for _, row := range typeRows {
		questionID, err := valueAsInt64(row["question_id"])
		if err != nil {
			return nil, err
		}
		idx, ok := indexByID[questionID]
		if !ok {
			continue
		}
		nameID, err := valueAsInt64(row["interview_name_id"])
		if err != nil {
			return nil, err
		}
		name, err := valueAsString(row["name"])
		if err != nil {
			return nil, err
		}
		out[idx].InterviewNameIDs = append(out[idx].InterviewNameIDs, nameID)
		out[idx].InterviewNames = append(out[idx].InterviewNames, name)
	}
	for i := range out {
		if len(out[i].InterviewNameIDs) > 0 {
			out[i].InterviewNameID = out[i].InterviewNameIDs[0]
			out[i].InterviewName = out[i].InterviewNames[0]
		}
	}
	return out, nil
}

func (s *sqliteStore) createCandidateInterviewQuestion(ctx context.Context, question candidateInterviewQuestion) (int64, error) {
	now := time.Now().UTC().Unix()
	params := map[string]string{
		"location_number": question.LocationNumber,
		"question":        strings.TrimSpace(question.Question),
		"response_type":   normalizeQuestionResponseType(question.ResponseType),
		"response_options": serializeQuestionResponseOptions(
			normalizeQuestionResponseOptions(question.ResponseOptions),
		),
		"created_at": strconv.FormatInt(now, 10),
		"updated_at": strconv.FormatInt(now, 10),
	}
	selectQuery := `
		SELECT id
		FROM location_candidate_interview_questions
		WHERE location_number = @location_number AND created_at = @created_at AND question = @question
	`
	_, err := s.exec(ctx, `
		INSERT INTO location_candidate_interview_questions (location_number, question, response_type, response_options, created_at, updated_at)
		VALUES (@location_number, @question, @response_type, @response_options, @created_at, @updated_at);
	`, params)
	if err != nil {
		return 0, err
	}
	rows, err := s.query(ctx, selectQuery+" ORDER BY id DESC LIMIT 1;", params)
	if err != nil {
		return 0, err
	}
	if len(rows) == 0 {
		return 0, errNotFound
	}
	return valueAsInt64(rows[0]["id"])
}

func (s *sqliteStore) updateCandidateInterviewQuestion(ctx context.Context, locationNumber string, questionID int64, interviewNameIDs []int64, question *string, responseType *string, responseOptions *[]string) error {
	rows, err := s.query(ctx, `
		SELECT COUNT(*) AS count
		FROM location_candidate_interview_questions
		WHERE id = @id AND location_number = @location_number;
	`, map[string]string{
		"id":              strconv.FormatInt(questionID, 10),
		"location_number": locationNumber,
	})
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		return errNotFound
	}
	count, err := valueAsInt64(rows[0]["count"])
	if err != nil {
		return err
	}
	if count == 0 {
		return errNotFound
	}
	_, err = s.exec(ctx, `
		DELETE FROM location_candidate_interview_question_types
		WHERE question_id = @question_id;
	`, map[string]string{
		"question_id": strconv.FormatInt(questionID, 10),
	})
	if err != nil {
		return err
	}
	for _, interviewNameID := range interviewNameIDs {
		if interviewNameID <= 0 {
			continue
		}
		_, err = s.exec(ctx, `
			INSERT OR IGNORE INTO location_candidate_interview_question_types (question_id, interview_name_id, created_at)
			VALUES (@question_id, @interview_name_id, @created_at);
		`, map[string]string{
			"question_id":       strconv.FormatInt(questionID, 10),
			"interview_name_id": strconv.FormatInt(interviewNameID, 10),
			"created_at":        strconv.FormatInt(time.Now().UTC().Unix(), 10),
		})
		if err != nil {
			return err
		}
	}
	updateParams := map[string]string{
		"id":              strconv.FormatInt(questionID, 10),
		"location_number": locationNumber,
		"updated_at":      strconv.FormatInt(time.Now().UTC().Unix(), 10),
	}
	setClauses := []string{"updated_at = @updated_at"}
	if question != nil {
		setClauses = append(setClauses, "question = @question")
		updateParams["question"] = strings.TrimSpace(*question)
	}
	if responseType != nil {
		setClauses = append(setClauses, "response_type = @response_type")
		updateParams["response_type"] = normalizeQuestionResponseType(*responseType)
	}
	if responseOptions != nil {
		setClauses = append(setClauses, "response_options = @response_options")
		updateParams["response_options"] = serializeQuestionResponseOptions(
			normalizeQuestionResponseOptions(*responseOptions),
		)
	}
	updateQuery := `
		UPDATE location_candidate_interview_questions
		SET ` + strings.Join(setClauses, ", ") + `
		WHERE id = @id AND location_number = @location_number;
	`
	_, err = s.exec(ctx, updateQuery, updateParams)
	return err
}

func (s *sqliteStore) deleteCandidateInterviewQuestion(ctx context.Context, locationNumber string, questionID int64) error {
	rows, err := s.query(ctx, `
		SELECT COUNT(*) AS count
		FROM location_candidate_interview_questions
		WHERE id = @id AND location_number = @location_number;
	`, map[string]string{
		"id":              strconv.FormatInt(questionID, 10),
		"location_number": locationNumber,
	})
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		return errNotFound
	}
	count, err := valueAsInt64(rows[0]["count"])
	if err != nil {
		return err
	}
	if count == 0 {
		return errNotFound
	}
	_, err = s.exec(ctx, `
		DELETE FROM location_candidate_interview_questions
		WHERE id = @id AND location_number = @location_number;
	`, map[string]string{
		"id":              strconv.FormatInt(questionID, 10),
		"location_number": locationNumber,
	})
	return err
}

func (s *sqliteStore) createCandidate(ctx context.Context, candidateRecord candidate) (int64, error) {
	now := time.Now().UTC().Unix()
	_, err := s.exec(ctx, `
		INSERT INTO location_candidates (location_number, first_name, last_name, phone, status, hired_time_punch_name, archived_at, created_at, updated_at)
		VALUES (@location_number, @first_name, @last_name, @phone, @status, @hired_time_punch_name, 0, @created_at, @updated_at);
	`, map[string]string{
		"location_number":       candidateRecord.LocationNumber,
		"first_name":            candidateRecord.FirstName,
		"last_name":             candidateRecord.LastName,
		"phone":                 strings.TrimSpace(candidateRecord.Phone),
		"status":                strings.TrimSpace(candidateRecord.Status),
		"hired_time_punch_name": strings.TrimSpace(candidateRecord.HiredTimePunchName),
		"created_at":            strconv.FormatInt(now, 10),
		"updated_at":            strconv.FormatInt(now, 10),
	})
	if err != nil {
		return 0, err
	}
	rows, err := s.query(ctx, `
		SELECT id
		FROM location_candidates
		WHERE location_number = @location_number
		ORDER BY id DESC
		LIMIT 1;
	`, map[string]string{"location_number": candidateRecord.LocationNumber})
	if err != nil {
		return 0, err
	}
	if len(rows) == 0 {
		return 0, errNotFound
	}
	return valueAsInt64(rows[0]["id"])
}

func (s *sqliteStore) deleteCandidate(ctx context.Context, locationNumber string, candidateID int64) error {
	if _, err := s.getCandidateByID(ctx, locationNumber, candidateID); err != nil {
		return err
	}
	_, err := s.exec(ctx, `
		DELETE FROM location_candidates
		WHERE id = @id AND location_number = @location_number;
	`, map[string]string{
		"id":              strconv.FormatInt(candidateID, 10),
		"location_number": locationNumber,
	})
	return err
}

func (s *sqliteStore) getCandidateByID(ctx context.Context, locationNumber string, candidateID int64) (*candidate, error) {
	rows, err := s.query(ctx, `
		SELECT id, location_number, first_name, last_name, phone, status, hired_time_punch_name, archived_at, created_at, updated_at
		FROM location_candidates
		WHERE id = @id AND location_number = @location_number
		LIMIT 1;
	`, map[string]string{
		"id":              strconv.FormatInt(candidateID, 10),
		"location_number": locationNumber,
	})
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, errNotFound
	}
	id, err := valueAsInt64(rows[0]["id"])
	if err != nil {
		return nil, err
	}
	loc, err := valueAsString(rows[0]["location_number"])
	if err != nil {
		return nil, err
	}
	firstName, err := valueAsString(rows[0]["first_name"])
	if err != nil {
		return nil, err
	}
	lastName, err := valueAsString(rows[0]["last_name"])
	if err != nil {
		return nil, err
	}
	phone, err := valueAsString(rows[0]["phone"])
	if err != nil {
		return nil, err
	}
	status, err := valueAsString(rows[0]["status"])
	if err != nil {
		return nil, err
	}
	hiredTPN, err := valueAsString(rows[0]["hired_time_punch_name"])
	if err != nil {
		return nil, err
	}
	archivedAtUnix, err := valueAsInt64(rows[0]["archived_at"])
	if err != nil {
		return nil, err
	}
	createdAtUnix, err := valueAsInt64(rows[0]["created_at"])
	if err != nil {
		return nil, err
	}
	updatedAtUnix, err := valueAsInt64(rows[0]["updated_at"])
	if err != nil {
		return nil, err
	}
	out := &candidate{
		ID:                 id,
		LocationNumber:     loc,
		FirstName:          firstName,
		LastName:           lastName,
		Phone:              phone,
		Status:             status,
		HiredTimePunchName: hiredTPN,
		CreatedAt:          time.Unix(createdAtUnix, 0).UTC(),
		UpdatedAt:          time.Unix(updatedAtUnix, 0).UTC(),
	}
	if archivedAtUnix > 0 {
		out.ArchivedAt = time.Unix(archivedAtUnix, 0).UTC()
	}
	return out, nil
}

func (s *sqliteStore) listCandidates(ctx context.Context, locationNumber string, archived bool, search string) ([]candidate, error) {
	search = strings.TrimSpace(search)
	statusFilter := "c.status = 'active'"
	if archived {
		statusFilter = "c.status IN ('passed', 'hired')"
	}
	query := `
		SELECT c.id, c.location_number, c.first_name, c.last_name, c.phone, c.status, c.hired_time_punch_name, c.archived_at, c.created_at, c.updated_at
		FROM location_candidates c
		WHERE c.location_number = @location_number
			AND ` + statusFilter
	params := map[string]string{"location_number": locationNumber}
	if search != "" {
		query += ` AND (LOWER(c.first_name) LIKE LOWER(@search) OR LOWER(c.last_name) LIKE LOWER(@search) OR LOWER(c.phone) LIKE LOWER(@search) OR LOWER(c.first_name || ' ' || c.last_name) LIKE LOWER(@search))`
		params["search"] = "%" + search + "%"
	}
	query += ` ORDER BY c.created_at DESC;`
	rows, err := s.query(ctx, query, params)
	if err != nil {
		return nil, err
	}
	out := make([]candidate, 0, len(rows))
	for _, row := range rows {
		id, err := valueAsInt64(row["id"])
		if err != nil {
			return nil, err
		}
		loc, err := valueAsString(row["location_number"])
		if err != nil {
			return nil, err
		}
		firstName, err := valueAsString(row["first_name"])
		if err != nil {
			return nil, err
		}
		lastName, err := valueAsString(row["last_name"])
		if err != nil {
			return nil, err
		}
		phone, err := valueAsString(row["phone"])
		if err != nil {
			return nil, err
		}
		status, err := valueAsString(row["status"])
		if err != nil {
			return nil, err
		}
		hiredTPN, err := valueAsString(row["hired_time_punch_name"])
		if err != nil {
			return nil, err
		}
		archivedAtUnix, err := valueAsInt64(row["archived_at"])
		if err != nil {
			return nil, err
		}
		createdAtUnix, err := valueAsInt64(row["created_at"])
		if err != nil {
			return nil, err
		}
		updatedAtUnix, err := valueAsInt64(row["updated_at"])
		if err != nil {
			return nil, err
		}
		record := candidate{
			ID:                 id,
			LocationNumber:     loc,
			FirstName:          firstName,
			LastName:           lastName,
			Phone:              phone,
			Status:             status,
			HiredTimePunchName: hiredTPN,
			CreatedAt:          time.Unix(createdAtUnix, 0).UTC(),
			UpdatedAt:          time.Unix(updatedAtUnix, 0).UTC(),
		}
		if archivedAtUnix > 0 {
			record.ArchivedAt = time.Unix(archivedAtUnix, 0).UTC()
		}
		out = append(out, record)
	}
	return out, nil
}

func (s *sqliteStore) listHiredCandidateScorecardsByTimePunchName(ctx context.Context, locationNumber, timePunchName string) ([]candidate, error) {
	rows, err := s.query(ctx, `
		SELECT id, location_number, first_name, last_name, phone, status, hired_time_punch_name, archived_at, created_at, updated_at
		FROM location_candidates
		WHERE location_number = @location_number
			AND status = 'hired'
			AND hired_time_punch_name = @hired_time_punch_name
		ORDER BY archived_at DESC, id DESC;
	`, map[string]string{
		"location_number":       locationNumber,
		"hired_time_punch_name": strings.TrimSpace(timePunchName),
	})
	if err != nil {
		return nil, err
	}
	out := make([]candidate, 0, len(rows))
	for _, row := range rows {
		id, err := valueAsInt64(row["id"])
		if err != nil {
			return nil, err
		}
		record, err := s.getCandidateByID(ctx, locationNumber, id)
		if err != nil {
			return nil, err
		}
		interviews, err := s.listCandidateInterviews(ctx, locationNumber, id)
		if err != nil {
			return nil, err
		}
		record.Interviews = interviews
		record.AverageGradePercent = candidateAverageGradePercent(interviews)
		out = append(out, *record)
	}
	return out, nil
}

func (s *sqliteStore) createCandidateInterview(ctx context.Context, interview candidateInterview) (int64, error) {
	now := time.Now().UTC().Unix()
	insertParams := map[string]string{
		"candidate_id":                strconv.FormatInt(interview.CandidateID, 10),
		"location_number":             interview.LocationNumber,
		"interviewer_time_punch_name": interview.InterviewerTimePunchName,
		"interview_type":              interview.InterviewType,
		"notes":                       interview.Notes,
		"created_at":                  strconv.FormatInt(now, 10),
	}
	if _, err := s.exec(ctx, `
		INSERT INTO location_candidate_interviews (candidate_id, location_number, interviewer_time_punch_name, interview_type, notes, created_at)
		VALUES (@candidate_id, @location_number, @interviewer_time_punch_name, @interview_type, @notes, @created_at);
	`, insertParams); err != nil {
		return 0, err
	}
	rows, err := s.query(ctx, `
		SELECT id
		FROM location_candidate_interviews
		WHERE candidate_id = @candidate_id AND location_number = @location_number
		ORDER BY id DESC
		LIMIT 1;
	`, map[string]string{
		"candidate_id":    strconv.FormatInt(interview.CandidateID, 10),
		"location_number": interview.LocationNumber,
	})
	if err != nil {
		return 0, err
	}
	if len(rows) == 0 {
		return 0, errNotFound
	}
	interviewID, err := valueAsInt64(rows[0]["id"])
	if err != nil {
		return 0, err
	}
	for _, grade := range interview.Grades {
		if _, err := s.exec(ctx, `
			INSERT INTO location_candidate_interview_grades (interview_id, value_id, letter_grade, grade_comment, created_at)
			VALUES (@interview_id, @value_id, @letter_grade, @grade_comment, @created_at);
		`, map[string]string{
			"interview_id":  strconv.FormatInt(interviewID, 10),
			"value_id":      strconv.FormatInt(grade.ValueID, 10),
			"letter_grade":  grade.LetterGrade,
			"grade_comment": strings.TrimSpace(grade.Comment),
			"created_at":    strconv.FormatInt(now, 10),
		}); err != nil {
			return 0, err
		}
	}
	for _, answer := range interview.QuestionAnswers {
		if _, err := s.exec(ctx, `
			INSERT INTO location_candidate_interview_question_answers (interview_id, question_id, question_text_snapshot, answer, created_at)
			VALUES (@interview_id, @question_id, @question_text_snapshot, @answer, @created_at);
		`, map[string]string{
			"interview_id":           strconv.FormatInt(interviewID, 10),
			"question_id":            strconv.FormatInt(answer.QuestionID, 10),
			"question_text_snapshot": strings.TrimSpace(answer.QuestionText),
			"answer":                 strings.TrimSpace(answer.Answer),
			"created_at":             strconv.FormatInt(now, 10),
		}); err != nil {
			return 0, err
		}
	}
	if _, err := s.exec(ctx, `
		UPDATE location_candidates
		SET updated_at = @updated_at
		WHERE id = @candidate_id AND location_number = @location_number;
	`, map[string]string{
		"updated_at":      strconv.FormatInt(now, 10),
		"candidate_id":    strconv.FormatInt(interview.CandidateID, 10),
		"location_number": interview.LocationNumber,
	}); err != nil {
		return 0, err
	}
	return interviewID, nil
}

func (s *sqliteStore) listCandidateInterviews(ctx context.Context, locationNumber string, candidateID int64) ([]candidateInterview, error) {
	rows, err := s.query(ctx, `
		SELECT i.id, i.candidate_id, i.location_number, i.interviewer_time_punch_name, i.interview_type, i.notes, i.created_at
		FROM location_candidate_interviews i
		LEFT JOIN location_candidate_interview_names n
			ON n.location_number = i.location_number AND n.name = i.interview_type
		WHERE i.location_number = @location_number AND i.candidate_id = @candidate_id
		ORDER BY COALESCE(n.priority, 2147483647) ASC, i.created_at ASC, i.id ASC;
	`, map[string]string{
		"location_number": locationNumber,
		"candidate_id":    strconv.FormatInt(candidateID, 10),
	})
	if err != nil {
		return nil, err
	}
	out := make([]candidateInterview, 0, len(rows))
	for _, row := range rows {
		id, err := valueAsInt64(row["id"])
		if err != nil {
			return nil, err
		}
		cid, err := valueAsInt64(row["candidate_id"])
		if err != nil {
			return nil, err
		}
		loc, err := valueAsString(row["location_number"])
		if err != nil {
			return nil, err
		}
		interviewerTPN, err := valueAsString(row["interviewer_time_punch_name"])
		if err != nil {
			return nil, err
		}
		interviewType, err := valueAsString(row["interview_type"])
		if err != nil {
			return nil, err
		}
		notes, err := valueAsString(row["notes"])
		if err != nil {
			return nil, err
		}
		createdAtUnix, err := valueAsInt64(row["created_at"])
		if err != nil {
			return nil, err
		}
		grades, err := s.listCandidateInterviewGrades(ctx, id)
		if err != nil {
			return nil, err
		}
		questionAnswers, err := s.listCandidateInterviewQuestionAnswers(ctx, id)
		if err != nil {
			return nil, err
		}
		out = append(out, candidateInterview{
			ID:                       id,
			CandidateID:              cid,
			LocationNumber:           loc,
			InterviewerTimePunchName: interviewerTPN,
			InterviewType:            interviewType,
			Notes:                    notes,
			CreatedAt:                time.Unix(createdAtUnix, 0).UTC(),
			Grades:                   grades,
			QuestionAnswers:          questionAnswers,
		})
	}
	return out, nil
}

func (s *sqliteStore) listCandidateInterviewGrades(ctx context.Context, interviewID int64) ([]candidateInterviewGrade, error) {
	rows, err := s.query(ctx, `
		SELECT g.id, g.interview_id, g.value_id, g.letter_grade, g.grade_comment, v.name AS value_name
		FROM location_candidate_interview_grades g
		INNER JOIN location_candidate_values v ON v.id = g.value_id
		WHERE g.interview_id = @interview_id
		ORDER BY g.id ASC;
	`, map[string]string{
		"interview_id": strconv.FormatInt(interviewID, 10),
	})
	if err != nil {
		return nil, err
	}
	out := make([]candidateInterviewGrade, 0, len(rows))
	for _, row := range rows {
		id, err := valueAsInt64(row["id"])
		if err != nil {
			return nil, err
		}
		iid, err := valueAsInt64(row["interview_id"])
		if err != nil {
			return nil, err
		}
		valueID, err := valueAsInt64(row["value_id"])
		if err != nil {
			return nil, err
		}
		letterGrade, err := valueAsString(row["letter_grade"])
		if err != nil {
			return nil, err
		}
		gradeComment, err := valueAsString(row["grade_comment"])
		if err != nil {
			return nil, err
		}
		valueName, err := valueAsString(row["value_name"])
		if err != nil {
			return nil, err
		}
		out = append(out, candidateInterviewGrade{
			ID:          id,
			InterviewID: iid,
			ValueID:     valueID,
			ValueName:   valueName,
			LetterGrade: letterGrade,
			Comment:     gradeComment,
			Score:       letterGradeScore(letterGrade),
		})
	}
	return out, nil
}

func (s *sqliteStore) listCandidateInterviewQuestionAnswers(ctx context.Context, interviewID int64) ([]candidateInterviewQuestionAnswer, error) {
	rows, err := s.query(ctx, `
		SELECT a.id, a.interview_id, a.question_id, a.answer,
			COALESCE(NULLIF(TRIM(a.question_text_snapshot), ''), COALESCE(NULLIF(TRIM(q.question), ''), 'Question #' || a.question_id)) AS question_text
		FROM location_candidate_interview_question_answers a
		LEFT JOIN location_candidate_interview_questions q ON q.id = a.question_id
		WHERE a.interview_id = @interview_id
		ORDER BY a.id ASC;
	`, map[string]string{
		"interview_id": strconv.FormatInt(interviewID, 10),
	})
	if err != nil {
		return nil, err
	}
	out := make([]candidateInterviewQuestionAnswer, 0, len(rows))
	for _, row := range rows {
		id, err := valueAsInt64(row["id"])
		if err != nil {
			return nil, err
		}
		iid, err := valueAsInt64(row["interview_id"])
		if err != nil {
			return nil, err
		}
		questionID, err := valueAsInt64(row["question_id"])
		if err != nil {
			return nil, err
		}
		answer, err := valueAsString(row["answer"])
		if err != nil {
			return nil, err
		}
		questionText, err := valueAsString(row["question_text"])
		if err != nil {
			return nil, err
		}
		out = append(out, candidateInterviewQuestionAnswer{
			ID:           id,
			InterviewID:  iid,
			QuestionID:   questionID,
			QuestionText: questionText,
			Answer:       answer,
		})
	}
	return out, nil
}

func (s *sqliteStore) updateCandidateStatus(ctx context.Context, locationNumber string, candidateID int64, status string, hiredTimePunchName string) error {
	now := time.Now().UTC().Unix()
	archivedAt := int64(0)
	if status == "passed" || status == "hired" {
		archivedAt = now
	}
	_, err := s.exec(ctx, `
		UPDATE location_candidates
		SET status = @status, hired_time_punch_name = @hired_time_punch_name, archived_at = @archived_at, updated_at = @updated_at
		WHERE id = @id AND location_number = @location_number;
	`, map[string]string{
		"id":                    strconv.FormatInt(candidateID, 10),
		"location_number":       locationNumber,
		"status":                status,
		"hired_time_punch_name": strings.TrimSpace(hiredTimePunchName),
		"archived_at":           strconv.FormatInt(archivedAt, 10),
		"updated_at":            strconv.FormatInt(now, 10),
	})
	if err != nil {
		return err
	}
	return nil
}

func (s *sqliteStore) countEmployeesForLocation(ctx context.Context, number string) (int, error) {
	rows, err := s.query(ctx, `
		SELECT COUNT(*) AS count
		FROM location_employees
		WHERE location_number = @location_number;
	`, map[string]string{"location_number": number})
	if err != nil {
		return 0, err
	}
	if len(rows) == 0 {
		return 0, nil
	}
	count, err := valueAsInt64(rows[0]["count"])
	if err != nil {
		return 0, err
	}
	return int(count), nil
}

func (s *sqliteStore) listLocationEmployees(ctx context.Context, number string) ([]employee, error) {
	rows, err := s.query(ctx, `
		SELECT e.time_punch_name, e.employee_number, e.first_name, e.last_name, e.department, e.job_id, COALESCE(j.name, '') AS job_name,
			0 AS department_id, e.department AS department_name,
			e.pay_type, e.pay_amount_cents,
			COALESCE(c.total_cents, 0) AS additional_comp_cents,
			(e.pay_amount_cents + COALESCE(c.total_cents, 0)) AS effective_pay_cents,
			e.birthday, e.email, e.phone, e.address, e.apt_number, e.city, e.state, e.zip_code,
			CASE WHEN LENGTH(COALESCE(profile_image_data, '')) > 0 THEN 1 ELSE 0 END AS has_photo,
			CASE WHEN EXISTS (
				SELECT 1 FROM users u
				WHERE u.role = @team_role
					AND u.location_number = e.location_number
					AND u.time_punch_name = e.time_punch_name
			) THEN 1 ELSE 0 END AS has_clock_in_pin,
			CASE WHEN EXISTS (
				SELECT 1 FROM employee_i9_forms i
				WHERE i.location_number = e.location_number
					AND i.time_punch_name = e.time_punch_name
					AND LENGTH(COALESCE(i.file_data, '')) > 0
			) AND EXISTS (
				SELECT 1 FROM employee_w4_forms w
				WHERE w.location_number = e.location_number
					AND w.time_punch_name = e.time_punch_name
					AND LENGTH(COALESCE(w.file_data, '')) > 0
			) THEN 1 ELSE 0 END AS has_completed_paperwork
		FROM location_employees e
		LEFT JOIN location_jobs j ON j.id = e.job_id AND j.location_number = e.location_number
		LEFT JOIN (
			SELECT location_number, time_punch_name, SUM(amount_cents) AS total_cents
			FROM employee_additional_compensations
			GROUP BY location_number, time_punch_name
		) c ON c.location_number = e.location_number AND c.time_punch_name = e.time_punch_name
		WHERE e.location_number = @location_number;
	`, map[string]string{
		"location_number": number,
		"team_role":       userRoleTeam,
	})
	if err != nil {
		return nil, err
	}
	employees := make([]employee, 0, len(rows))
	for _, row := range rows {
		timePunchName, err := valueAsString(row["time_punch_name"])
		if err != nil {
			return nil, err
		}
		employeeNumber, err := valueAsString(row["employee_number"])
		if err != nil {
			return nil, err
		}
		firstName, err := valueAsString(row["first_name"])
		if err != nil {
			return nil, err
		}
		lastName, err := valueAsString(row["last_name"])
		if err != nil {
			return nil, err
		}
		jobID, err := valueAsInt64(row["job_id"])
		if err != nil {
			return nil, err
		}
		jobName, err := valueAsString(row["job_name"])
		if err != nil {
			return nil, err
		}
		departmentID, err := valueAsInt64(row["department_id"])
		if err != nil {
			return nil, err
		}
		departmentName, err := valueAsString(row["department_name"])
		if err != nil {
			return nil, err
		}
		payType, err := valueAsString(row["pay_type"])
		if err != nil {
			return nil, err
		}
		payAmountCents, err := valueAsInt64(row["pay_amount_cents"])
		if err != nil {
			return nil, err
		}
		additionalCompCents, err := valueAsInt64(row["additional_comp_cents"])
		if err != nil {
			return nil, err
		}
		effectivePayCents, err := valueAsInt64(row["effective_pay_cents"])
		if err != nil {
			return nil, err
		}
		birthday, err := valueAsString(row["birthday"])
		if err != nil {
			return nil, err
		}
		email, err := valueAsString(row["email"])
		if err != nil {
			return nil, err
		}
		phone, err := valueAsString(row["phone"])
		if err != nil {
			return nil, err
		}
		address, err := valueAsString(row["address"])
		if err != nil {
			return nil, err
		}
		aptNumber, err := valueAsString(row["apt_number"])
		if err != nil {
			return nil, err
		}
		city, err := valueAsString(row["city"])
		if err != nil {
			return nil, err
		}
		state, err := valueAsString(row["state"])
		if err != nil {
			return nil, err
		}
		zipCode, err := valueAsString(row["zip_code"])
		if err != nil {
			return nil, err
		}
		hasPhotoRaw, err := valueAsInt64(row["has_photo"])
		if err != nil {
			return nil, err
		}
		hasClockInPINRaw, err := valueAsInt64(row["has_clock_in_pin"])
		if err != nil {
			return nil, err
		}
		hasCompletedPaperworkRaw, err := valueAsInt64(row["has_completed_paperwork"])
		if err != nil {
			return nil, err
		}
		employees = append(employees, employee{
			FirstName:             firstName,
			LastName:              lastName,
			TimePunchName:         timePunchName,
			EmployeeNumber:        strings.TrimSpace(employeeNumber),
			Department:            normalizeDepartment(departmentName),
			DepartmentID:          departmentID,
			JobID:                 jobID,
			JobName:               strings.TrimSpace(jobName),
			PayBandID:             jobID,
			PayBandName:           strings.TrimSpace(jobName),
			PayType:               strings.TrimSpace(payType),
			PayAmountCents:        payAmountCents,
			AdditionalCompCents:   additionalCompCents,
			EffectivePayCents:     effectivePayCents,
			Birthday:              birthday,
			Email:                 email,
			Phone:                 phone,
			Address:               address,
			AptNumber:             aptNumber,
			City:                  city,
			State:                 state,
			ZipCode:               zipCode,
			HasPhoto:              hasPhotoRaw == 1,
			HasClockInPIN:         hasClockInPINRaw == 1,
			HasCompletedPaperwork: hasCompletedPaperworkRaw == 1,
		})
	}
	return employees, nil
}

func (s *sqliteStore) getLocationEmployee(ctx context.Context, locationNumber, timePunchName string) (*employee, error) {
	rows, err := s.query(ctx, `
		SELECT e.time_punch_name, e.employee_number, e.first_name, e.last_name, e.department, e.job_id, COALESCE(j.name, '') AS job_name,
			0 AS department_id, e.department AS department_name,
			e.pay_type, e.pay_amount_cents,
			COALESCE(c.total_cents, 0) AS additional_comp_cents,
			(e.pay_amount_cents + COALESCE(c.total_cents, 0)) AS effective_pay_cents,
			e.birthday, e.email, e.phone, e.address, e.apt_number, e.city, e.state, e.zip_code,
			CASE WHEN LENGTH(COALESCE(profile_image_data, '')) > 0 THEN 1 ELSE 0 END AS has_photo,
			CASE WHEN EXISTS (
				SELECT 1 FROM users u
				WHERE u.role = @team_role
					AND u.location_number = e.location_number
					AND u.time_punch_name = e.time_punch_name
			) THEN 1 ELSE 0 END AS has_clock_in_pin,
			CASE WHEN EXISTS (
				SELECT 1 FROM employee_i9_forms i
				WHERE i.location_number = e.location_number
					AND i.time_punch_name = e.time_punch_name
					AND LENGTH(COALESCE(i.file_data, '')) > 0
			) AND EXISTS (
				SELECT 1 FROM employee_w4_forms w
				WHERE w.location_number = e.location_number
					AND w.time_punch_name = e.time_punch_name
					AND LENGTH(COALESCE(w.file_data, '')) > 0
			) THEN 1 ELSE 0 END AS has_completed_paperwork
		FROM location_employees e
		LEFT JOIN location_jobs j ON j.id = e.job_id AND j.location_number = e.location_number
		LEFT JOIN (
			SELECT location_number, time_punch_name, SUM(amount_cents) AS total_cents
			FROM employee_additional_compensations
			GROUP BY location_number, time_punch_name
		) c ON c.location_number = e.location_number AND c.time_punch_name = e.time_punch_name
		WHERE e.location_number = @location_number
			AND e.time_punch_name = @time_punch_name
		LIMIT 1;
	`, map[string]string{
		"location_number": locationNumber,
		"time_punch_name": timePunchName,
		"team_role":       userRoleTeam,
	})
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, errNotFound
	}
	employeeNumber, err := valueAsString(rows[0]["employee_number"])
	if err != nil {
		return nil, err
	}
	firstName, err := valueAsString(rows[0]["first_name"])
	if err != nil {
		return nil, err
	}
	lastName, err := valueAsString(rows[0]["last_name"])
	if err != nil {
		return nil, err
	}
	tpn, err := valueAsString(rows[0]["time_punch_name"])
	if err != nil {
		return nil, err
	}
	jobID, err := valueAsInt64(rows[0]["job_id"])
	if err != nil {
		return nil, err
	}
	jobName, err := valueAsString(rows[0]["job_name"])
	if err != nil {
		return nil, err
	}
	departmentID, err := valueAsInt64(rows[0]["department_id"])
	if err != nil {
		return nil, err
	}
	departmentName, err := valueAsString(rows[0]["department_name"])
	if err != nil {
		return nil, err
	}
	payType, err := valueAsString(rows[0]["pay_type"])
	if err != nil {
		return nil, err
	}
	payAmountCents, err := valueAsInt64(rows[0]["pay_amount_cents"])
	if err != nil {
		return nil, err
	}
	additionalCompCents, err := valueAsInt64(rows[0]["additional_comp_cents"])
	if err != nil {
		return nil, err
	}
	effectivePayCents, err := valueAsInt64(rows[0]["effective_pay_cents"])
	if err != nil {
		return nil, err
	}
	birthday, err := valueAsString(rows[0]["birthday"])
	if err != nil {
		return nil, err
	}
	email, err := valueAsString(rows[0]["email"])
	if err != nil {
		return nil, err
	}
	phone, err := valueAsString(rows[0]["phone"])
	if err != nil {
		return nil, err
	}
	address, err := valueAsString(rows[0]["address"])
	if err != nil {
		return nil, err
	}
	aptNumber, err := valueAsString(rows[0]["apt_number"])
	if err != nil {
		return nil, err
	}
	city, err := valueAsString(rows[0]["city"])
	if err != nil {
		return nil, err
	}
	state, err := valueAsString(rows[0]["state"])
	if err != nil {
		return nil, err
	}
	zipCode, err := valueAsString(rows[0]["zip_code"])
	if err != nil {
		return nil, err
	}
	hasPhotoRaw, err := valueAsInt64(rows[0]["has_photo"])
	if err != nil {
		return nil, err
	}
	hasClockInPINRaw, err := valueAsInt64(rows[0]["has_clock_in_pin"])
	if err != nil {
		return nil, err
	}
	hasCompletedPaperworkRaw, err := valueAsInt64(rows[0]["has_completed_paperwork"])
	if err != nil {
		return nil, err
	}
	return &employee{
		FirstName:             firstName,
		LastName:              lastName,
		TimePunchName:         tpn,
		EmployeeNumber:        strings.TrimSpace(employeeNumber),
		Department:            normalizeDepartment(departmentName),
		DepartmentID:          departmentID,
		JobID:                 jobID,
		JobName:               strings.TrimSpace(jobName),
		PayBandID:             jobID,
		PayBandName:           strings.TrimSpace(jobName),
		PayType:               strings.TrimSpace(payType),
		PayAmountCents:        payAmountCents,
		AdditionalCompCents:   additionalCompCents,
		EffectivePayCents:     effectivePayCents,
		Birthday:              birthday,
		Email:                 email,
		Phone:                 phone,
		Address:               address,
		AptNumber:             aptNumber,
		City:                  city,
		State:                 state,
		ZipCode:               zipCode,
		HasPhoto:              hasPhotoRaw == 1,
		HasClockInPIN:         hasClockInPINRaw == 1,
		HasCompletedPaperwork: hasCompletedPaperworkRaw == 1,
	}, nil
}

func (s *sqliteStore) listArchivedLocationEmployees(ctx context.Context, number string) ([]employee, error) {
	rows, err := s.query(ctx, `
		SELECT time_punch_name, employee_number, first_name, last_name, department, job_id, pay_type, pay_amount_cents, birthday, email, phone, address, apt_number, city, state, zip_code,
			CASE WHEN LENGTH(COALESCE(profile_image_data, '')) > 0 THEN 1 ELSE 0 END AS has_photo,
			archived_at
		FROM archived_location_employees
		WHERE location_number = @location_number
		ORDER BY archived_at DESC;
	`, map[string]string{"location_number": number})
	if err != nil {
		return nil, err
	}
	employees := make([]employee, 0, len(rows))
	for _, row := range rows {
		timePunchName, err := valueAsString(row["time_punch_name"])
		if err != nil {
			return nil, err
		}
		employeeNumber, err := valueAsString(row["employee_number"])
		if err != nil {
			return nil, err
		}
		firstName, err := valueAsString(row["first_name"])
		if err != nil {
			return nil, err
		}
		lastName, err := valueAsString(row["last_name"])
		if err != nil {
			return nil, err
		}
		department, err := valueAsString(row["department"])
		if err != nil {
			return nil, err
		}
		jobID, err := valueAsInt64(row["job_id"])
		if err != nil {
			return nil, err
		}
		payType, err := valueAsString(row["pay_type"])
		if err != nil {
			return nil, err
		}
		payAmountCents, err := valueAsInt64(row["pay_amount_cents"])
		if err != nil {
			return nil, err
		}
		birthday, err := valueAsString(row["birthday"])
		if err != nil {
			return nil, err
		}
		email, err := valueAsString(row["email"])
		if err != nil {
			return nil, err
		}
		phone, err := valueAsString(row["phone"])
		if err != nil {
			return nil, err
		}
		address, err := valueAsString(row["address"])
		if err != nil {
			return nil, err
		}
		aptNumber, err := valueAsString(row["apt_number"])
		if err != nil {
			return nil, err
		}
		city, err := valueAsString(row["city"])
		if err != nil {
			return nil, err
		}
		state, err := valueAsString(row["state"])
		if err != nil {
			return nil, err
		}
		zipCode, err := valueAsString(row["zip_code"])
		if err != nil {
			return nil, err
		}
		hasPhotoRaw, err := valueAsInt64(row["has_photo"])
		if err != nil {
			return nil, err
		}
		archivedAtUnix, err := valueAsInt64(row["archived_at"])
		if err != nil {
			return nil, err
		}
		employees = append(employees, employee{
			FirstName:      firstName,
			LastName:       lastName,
			TimePunchName:  timePunchName,
			EmployeeNumber: strings.TrimSpace(employeeNumber),
			Department:     normalizeDepartment(department),
			JobID:          jobID,
			JobName:        "",
			PayBandID:      jobID,
			PayBandName:    "",
			PayType:        strings.TrimSpace(payType),
			PayAmountCents: payAmountCents,
			EffectivePayCents: payAmountCents,
			Birthday:       birthday,
			Email:          email,
			Phone:          phone,
			Address:        address,
			AptNumber:      aptNumber,
			City:           city,
			State:          state,
			ZipCode:        zipCode,
			HasPhoto:       hasPhotoRaw == 1,
			ArchivedAt:     time.Unix(archivedAtUnix, 0).UTC().Format(time.RFC3339),
		})
	}
	return employees, nil
}

func (s *sqliteStore) getArchivedLocationEmployee(ctx context.Context, locationNumber, timePunchName string) (*employee, error) {
	rows, err := s.query(ctx, `
		SELECT time_punch_name, employee_number, first_name, last_name, department, job_id, pay_type, pay_amount_cents, birthday, email, phone, address, apt_number, city, state, zip_code,
			CASE WHEN LENGTH(COALESCE(profile_image_data, '')) > 0 THEN 1 ELSE 0 END AS has_photo,
			archived_at
		FROM archived_location_employees
		WHERE location_number = @location_number
			AND time_punch_name = @time_punch_name
		LIMIT 1;
	`, map[string]string{
		"location_number": locationNumber,
		"time_punch_name": timePunchName,
	})
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, errNotFound
	}
	employeeNumber, err := valueAsString(rows[0]["employee_number"])
	if err != nil {
		return nil, err
	}
	firstName, err := valueAsString(rows[0]["first_name"])
	if err != nil {
		return nil, err
	}
	lastName, err := valueAsString(rows[0]["last_name"])
	if err != nil {
		return nil, err
	}
	tpn, err := valueAsString(rows[0]["time_punch_name"])
	if err != nil {
		return nil, err
	}
	dept, err := valueAsString(rows[0]["department"])
	if err != nil {
		return nil, err
	}
	jobID, err := valueAsInt64(rows[0]["job_id"])
	if err != nil {
		return nil, err
	}
	payType, err := valueAsString(rows[0]["pay_type"])
	if err != nil {
		return nil, err
	}
	payAmountCents, err := valueAsInt64(rows[0]["pay_amount_cents"])
	if err != nil {
		return nil, err
	}
	birthday, err := valueAsString(rows[0]["birthday"])
	if err != nil {
		return nil, err
	}
	email, err := valueAsString(rows[0]["email"])
	if err != nil {
		return nil, err
	}
	phone, err := valueAsString(rows[0]["phone"])
	if err != nil {
		return nil, err
	}
	address, err := valueAsString(rows[0]["address"])
	if err != nil {
		return nil, err
	}
	aptNumber, err := valueAsString(rows[0]["apt_number"])
	if err != nil {
		return nil, err
	}
	city, err := valueAsString(rows[0]["city"])
	if err != nil {
		return nil, err
	}
	state, err := valueAsString(rows[0]["state"])
	if err != nil {
		return nil, err
	}
	zipCode, err := valueAsString(rows[0]["zip_code"])
	if err != nil {
		return nil, err
	}
	hasPhotoRaw, err := valueAsInt64(rows[0]["has_photo"])
	if err != nil {
		return nil, err
	}
	archivedAtUnix, err := valueAsInt64(rows[0]["archived_at"])
	if err != nil {
		return nil, err
	}
	return &employee{
		FirstName:      firstName,
		LastName:       lastName,
		TimePunchName:  tpn,
		EmployeeNumber: strings.TrimSpace(employeeNumber),
		Department:     normalizeDepartment(dept),
		JobID:          jobID,
		JobName:        "",
		PayBandID:      jobID,
		PayBandName:    "",
		PayType:        strings.TrimSpace(payType),
		PayAmountCents: payAmountCents,
		EffectivePayCents: payAmountCents,
		Birthday:       birthday,
		Email:          email,
		Phone:          phone,
		Address:        address,
		AptNumber:      aptNumber,
		City:           city,
		State:          state,
		ZipCode:        zipCode,
		HasPhoto:       hasPhotoRaw == 1,
		ArchivedAt:     time.Unix(archivedAtUnix, 0).UTC().Format(time.RFC3339),
	}, nil
}

func (s *sqliteStore) getArchivedEmployeeRecord(ctx context.Context, locationNumber, timePunchName string) (*archivedEmployeeRecord, error) {
	rows, err := s.query(ctx, `
		SELECT id, location_number, time_punch_name, employee_number, first_name, last_name, department, job_id, birthday, email, phone, address, apt_number, city, state, zip_code, profile_image_data, profile_image_mime, archived_at
		FROM archived_location_employees
		WHERE location_number = @location_number
			AND time_punch_name = @time_punch_name
		LIMIT 1;
	`, map[string]string{
		"location_number": locationNumber,
		"time_punch_name": timePunchName,
	})
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, errNotFound
	}
	id, err := valueAsInt64(rows[0]["id"])
	if err != nil {
		return nil, err
	}
	employeeNumber, err := valueAsString(rows[0]["employee_number"])
	if err != nil {
		return nil, err
	}
	firstName, err := valueAsString(rows[0]["first_name"])
	if err != nil {
		return nil, err
	}
	lastName, err := valueAsString(rows[0]["last_name"])
	if err != nil {
		return nil, err
	}
	department, err := valueAsString(rows[0]["department"])
	if err != nil {
		return nil, err
	}
	jobID, err := valueAsInt64(rows[0]["job_id"])
	if err != nil {
		return nil, err
	}
	birthday, err := valueAsString(rows[0]["birthday"])
	if err != nil {
		return nil, err
	}
	email, err := valueAsString(rows[0]["email"])
	if err != nil {
		return nil, err
	}
	phone, err := valueAsString(rows[0]["phone"])
	if err != nil {
		return nil, err
	}
	address, err := valueAsString(rows[0]["address"])
	if err != nil {
		return nil, err
	}
	aptNumber, err := valueAsString(rows[0]["apt_number"])
	if err != nil {
		return nil, err
	}
	city, err := valueAsString(rows[0]["city"])
	if err != nil {
		return nil, err
	}
	state, err := valueAsString(rows[0]["state"])
	if err != nil {
		return nil, err
	}
	zipCode, err := valueAsString(rows[0]["zip_code"])
	if err != nil {
		return nil, err
	}
	profileData, err := valueAsString(rows[0]["profile_image_data"])
	if err != nil {
		return nil, err
	}
	profileMime, err := valueAsString(rows[0]["profile_image_mime"])
	if err != nil {
		return nil, err
	}
	archivedAtUnix, err := valueAsInt64(rows[0]["archived_at"])
	if err != nil {
		return nil, err
	}
	return &archivedEmployeeRecord{
		ID:             id,
		LocationNumber: locationNumber,
		TimePunchName:  timePunchName,
		EmployeeNumber: strings.TrimSpace(employeeNumber),
		FirstName:      firstName,
		LastName:       lastName,
		Department:     normalizeDepartment(department),
		JobID:          jobID,
		Birthday:       birthday,
		Email:          email,
		Phone:          phone,
		Address:        address,
		AptNumber:      aptNumber,
		City:           city,
		State:          state,
		ZipCode:        zipCode,
		ProfileImage:   profileData,
		ProfileMime:    profileMime,
		ArchivedAt:     time.Unix(archivedAtUnix, 0).UTC(),
	}, nil
}

func (s *sqliteStore) archiveAndDeleteLocationEmployee(ctx context.Context, locationNumber, timePunchName string) error {
	rows, err := s.query(ctx, `
		SELECT employee_number, first_name, last_name, department, job_id, pay_type, pay_amount_cents, birthday, email, phone, address, apt_number, city, state, zip_code, profile_image_data, profile_image_mime
		FROM location_employees
		WHERE location_number = @location_number AND time_punch_name = @time_punch_name
		LIMIT 1;
	`, map[string]string{
		"location_number": locationNumber,
		"time_punch_name": timePunchName,
	})
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		return errNotFound
	}
	employeeNumber, err := valueAsString(rows[0]["employee_number"])
	if err != nil {
		return err
	}
	firstName, err := valueAsString(rows[0]["first_name"])
	if err != nil {
		return err
	}
	lastName, err := valueAsString(rows[0]["last_name"])
	if err != nil {
		return err
	}
	department, err := valueAsString(rows[0]["department"])
	if err != nil {
		return err
	}
	jobID, err := valueAsInt64(rows[0]["job_id"])
	if err != nil {
		return err
	}
	payType, err := valueAsString(rows[0]["pay_type"])
	if err != nil {
		return err
	}
	payAmountCents, err := valueAsInt64(rows[0]["pay_amount_cents"])
	if err != nil {
		return err
	}
	birthday, err := valueAsString(rows[0]["birthday"])
	if err != nil {
		return err
	}
	email, err := valueAsString(rows[0]["email"])
	if err != nil {
		return err
	}
	phone, err := valueAsString(rows[0]["phone"])
	if err != nil {
		return err
	}
	address, err := valueAsString(rows[0]["address"])
	if err != nil {
		return err
	}
	aptNumber, err := valueAsString(rows[0]["apt_number"])
	if err != nil {
		return err
	}
	city, err := valueAsString(rows[0]["city"])
	if err != nil {
		return err
	}
	state, err := valueAsString(rows[0]["state"])
	if err != nil {
		return err
	}
	zipCode, err := valueAsString(rows[0]["zip_code"])
	if err != nil {
		return err
	}
	profileData, err := valueAsString(rows[0]["profile_image_data"])
	if err != nil {
		return err
	}
	profileMime, err := valueAsString(rows[0]["profile_image_mime"])
	if err != nil {
		return err
	}

	nowUnix := time.Now().UTC().Unix()
	stmt := `
		BEGIN;
		INSERT INTO archived_location_employees (
			location_number, time_punch_name, employee_number, first_name, last_name, department, job_id, pay_type, pay_amount_cents, birthday, email, phone, address, apt_number, city, state, zip_code, profile_image_data, profile_image_mime, archived_at
		) VALUES (
			` + sqliteStringLiteral(locationNumber) + `,
			` + sqliteStringLiteral(timePunchName) + `,
			` + sqliteStringLiteral(strings.TrimSpace(employeeNumber)) + `,
			` + sqliteStringLiteral(firstName) + `,
			` + sqliteStringLiteral(lastName) + `,
			` + sqliteStringLiteral(normalizeDepartment(department)) + `,
			` + strconv.FormatInt(jobID, 10) + `,
			` + sqliteStringLiteral(strings.TrimSpace(payType)) + `,
			` + strconv.FormatInt(payAmountCents, 10) + `,
			` + sqliteStringLiteral(birthday) + `,
			` + sqliteStringLiteral(email) + `,
			` + sqliteStringLiteral(phone) + `,
			` + sqliteStringLiteral(address) + `,
			` + sqliteStringLiteral(aptNumber) + `,
			` + sqliteStringLiteral(city) + `,
			` + sqliteStringLiteral(state) + `,
			` + sqliteStringLiteral(zipCode) + `,
			` + sqliteStringLiteral(profileData) + `,
			` + sqliteStringLiteral(profileMime) + `,
			` + strconv.FormatInt(nowUnix, 10) + `
		)
		ON CONFLICT(location_number, time_punch_name)
		DO UPDATE SET
			employee_number = excluded.employee_number,
			first_name = excluded.first_name,
			last_name = excluded.last_name,
			department = excluded.department,
			job_id = excluded.job_id,
			pay_type = excluded.pay_type,
			pay_amount_cents = excluded.pay_amount_cents,
			birthday = excluded.birthday,
			email = excluded.email,
			phone = excluded.phone,
			address = excluded.address,
			apt_number = excluded.apt_number,
			city = excluded.city,
			state = excluded.state,
			zip_code = excluded.zip_code,
			profile_image_data = excluded.profile_image_data,
			profile_image_mime = excluded.profile_image_mime,
			archived_at = excluded.archived_at;

		INSERT INTO archived_employee_i9_forms (
			archived_employee_id, file_data, file_mime, file_name, updated_at, created_at
		)
		SELECT a.id, f.file_data, f.file_mime, f.file_name, f.updated_at, f.created_at
		FROM employee_i9_forms f
		INNER JOIN archived_location_employees a
			ON a.location_number = f.location_number
			AND a.time_punch_name = f.time_punch_name
		WHERE f.location_number = ` + sqliteStringLiteral(locationNumber) + `
			AND f.time_punch_name = ` + sqliteStringLiteral(timePunchName) + `
		ON CONFLICT(archived_employee_id)
		DO UPDATE SET
			file_data = excluded.file_data,
			file_mime = excluded.file_mime,
			file_name = excluded.file_name,
			updated_at = excluded.updated_at;

		INSERT INTO archived_employee_w4_forms (
			archived_employee_id, file_data, file_mime, file_name, updated_at, created_at
		)
		SELECT a.id, f.file_data, f.file_mime, f.file_name, f.updated_at, f.created_at
		FROM employee_w4_forms f
		INNER JOIN archived_location_employees a
			ON a.location_number = f.location_number
			AND a.time_punch_name = f.time_punch_name
		WHERE f.location_number = ` + sqliteStringLiteral(locationNumber) + `
			AND f.time_punch_name = ` + sqliteStringLiteral(timePunchName) + `
		ON CONFLICT(archived_employee_id)
		DO UPDATE SET
			file_data = excluded.file_data,
			file_mime = excluded.file_mime,
			file_name = excluded.file_name,
			updated_at = excluded.updated_at;

		DELETE FROM archived_employee_i9_documents
		WHERE archived_employee_id = (
			SELECT id FROM archived_location_employees
			WHERE location_number = ` + sqliteStringLiteral(locationNumber) + `
				AND time_punch_name = ` + sqliteStringLiteral(timePunchName) + `
			LIMIT 1
		);

		INSERT INTO archived_employee_i9_documents (
			archived_employee_id, list_type, document_title, issuing_authority, document_number, expiration_date, file_data, file_mime, file_name, created_at
		)
		SELECT a.id, d.list_type, d.document_title, d.issuing_authority, d.document_number, d.expiration_date, d.file_data, d.file_mime, d.file_name, d.created_at
		FROM employee_i9_documents d
		INNER JOIN archived_location_employees a
			ON a.location_number = d.location_number
			AND a.time_punch_name = d.time_punch_name
		WHERE d.location_number = ` + sqliteStringLiteral(locationNumber) + `
			AND d.time_punch_name = ` + sqliteStringLiteral(timePunchName) + `;

		DELETE FROM employee_i9_documents
		WHERE location_number = ` + sqliteStringLiteral(locationNumber) + `
			AND time_punch_name = ` + sqliteStringLiteral(timePunchName) + `;

		DELETE FROM employee_i9_forms
		WHERE location_number = ` + sqliteStringLiteral(locationNumber) + `
			AND time_punch_name = ` + sqliteStringLiteral(timePunchName) + `;

		DELETE FROM employee_w4_forms
		WHERE location_number = ` + sqliteStringLiteral(locationNumber) + `
			AND time_punch_name = ` + sqliteStringLiteral(timePunchName) + `;

		DELETE FROM location_employees
		WHERE location_number = ` + sqliteStringLiteral(locationNumber) + `
			AND time_punch_name = ` + sqliteStringLiteral(timePunchName) + `;
		COMMIT;
	`
	_, err = s.exec(ctx, stmt, nil)
	return err
}

func (s *sqliteStore) upsertEmployeeI9Form(ctx context.Context, locationNumber, timePunchName string, data []byte, mime, fileName string) error {
	encoded := base64.StdEncoding.EncodeToString(data)
	now := time.Now().UTC().Unix()
	existingRows, err := s.query(ctx, `
		SELECT file_data, file_mime, file_name, updated_at
		FROM employee_i9_forms
		WHERE location_number = @location_number AND time_punch_name = @time_punch_name
		LIMIT 1;
	`, map[string]string{
		"location_number": locationNumber,
		"time_punch_name": timePunchName,
	})
	if err != nil {
		return err
	}
	if len(existingRows) > 0 {
		existingData, err := valueAsString(existingRows[0]["file_data"])
		if err != nil {
			return err
		}
		existingMime, err := valueAsString(existingRows[0]["file_mime"])
		if err != nil {
			return err
		}
		existingName, err := valueAsString(existingRows[0]["file_name"])
		if err != nil {
			return err
		}
		existingUpdatedAt, err := valueAsInt64(existingRows[0]["updated_at"])
		if err != nil {
			return err
		}
		if strings.TrimSpace(existingData) != "" {
			historyCreatedAt := now
			if existingUpdatedAt > 0 {
				historyCreatedAt = existingUpdatedAt
			}
			if _, err := s.exec(ctx, `
				INSERT INTO employee_i9_form_history (
					location_number, time_punch_name, file_data, file_mime, file_name, created_at
				)
				VALUES (
					@location_number, @time_punch_name, @file_data, @file_mime, @file_name, @created_at
				);
			`, map[string]string{
				"location_number": locationNumber,
				"time_punch_name": timePunchName,
				"file_data":       existingData,
				"file_mime":       existingMime,
				"file_name":       existingName,
				"created_at":      strconv.FormatInt(historyCreatedAt, 10),
			}); err != nil {
				return err
			}
		}
	}
	_, err = s.exec(ctx, `
		INSERT INTO employee_i9_forms (
			location_number, time_punch_name, file_data, file_mime, file_name, updated_at, created_at
		)
		VALUES (
			@location_number, @time_punch_name, @file_data, @file_mime, @file_name, @updated_at, @created_at
		)
		ON CONFLICT(location_number, time_punch_name)
		DO UPDATE SET
			file_data = excluded.file_data,
			file_mime = excluded.file_mime,
			file_name = excluded.file_name,
			updated_at = excluded.updated_at;
	`, map[string]string{
		"location_number": locationNumber,
		"time_punch_name": timePunchName,
		"file_data":       encoded,
		"file_mime":       mime,
		"file_name":       fileName,
		"updated_at":      strconv.FormatInt(now, 10),
		"created_at":      strconv.FormatInt(now, 10),
	})
	return err
}

func (s *sqliteStore) getEmployeeI9Form(ctx context.Context, locationNumber, timePunchName string) (employeeI9Form, error) {
	rows, err := s.query(ctx, `
		SELECT file_name, file_mime, updated_at, created_at
		FROM employee_i9_forms
		WHERE location_number = @location_number AND time_punch_name = @time_punch_name
		LIMIT 1;
	`, map[string]string{
		"location_number": locationNumber,
		"time_punch_name": timePunchName,
	})
	if err != nil {
		return employeeI9Form{}, err
	}
	if len(rows) == 0 {
		return employeeI9Form{
			LocationNumber: locationNumber,
			TimePunchName:  timePunchName,
			HasFile:        false,
		}, nil
	}
	fileName, err := valueAsString(rows[0]["file_name"])
	if err != nil {
		return employeeI9Form{}, err
	}
	fileMime, err := valueAsString(rows[0]["file_mime"])
	if err != nil {
		return employeeI9Form{}, err
	}
	updatedUnix, err := valueAsInt64(rows[0]["updated_at"])
	if err != nil {
		return employeeI9Form{}, err
	}
	createdUnix, err := valueAsInt64(rows[0]["created_at"])
	if err != nil {
		return employeeI9Form{}, err
	}
	return employeeI9Form{
		LocationNumber: locationNumber,
		TimePunchName:  timePunchName,
		FileName:       fileName,
		FileMime:       fileMime,
		UpdatedAt:      time.Unix(updatedUnix, 0).UTC(),
		CreatedAt:      time.Unix(createdUnix, 0).UTC(),
		HasFile:        true,
	}, nil
}

func (s *sqliteStore) getEmployeeI9File(ctx context.Context, locationNumber, timePunchName string) ([]byte, string, string, error) {
	rows, err := s.query(ctx, `
		SELECT file_data, file_mime, file_name
		FROM employee_i9_forms
		WHERE location_number = @location_number AND time_punch_name = @time_punch_name
		LIMIT 1;
	`, map[string]string{
		"location_number": locationNumber,
		"time_punch_name": timePunchName,
	})
	if err != nil {
		return nil, "", "", err
	}
	if len(rows) == 0 {
		return nil, "", "", errNotFound
	}
	encoded, err := valueAsString(rows[0]["file_data"])
	if err != nil {
		return nil, "", "", err
	}
	if strings.TrimSpace(encoded) == "" {
		return nil, "", "", errNotFound
	}
	fileBytes, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, "", "", err
	}
	fileMime, _ := valueAsString(rows[0]["file_mime"])
	fileName, _ := valueAsString(rows[0]["file_name"])
	if strings.TrimSpace(fileMime) == "" {
		fileMime = "application/pdf"
	}
	return fileBytes, fileMime, fileName, nil
}

func (s *sqliteStore) listEmployeeI9FormHistory(ctx context.Context, locationNumber, timePunchName string) ([]paperworkHistoryEntry, error) {
	rows, err := s.query(ctx, `
		SELECT id, file_name, file_mime, created_at
		FROM employee_i9_form_history
		WHERE location_number = @location_number AND time_punch_name = @time_punch_name
		ORDER BY created_at DESC, id DESC;
	`, map[string]string{
		"location_number": locationNumber,
		"time_punch_name": timePunchName,
	})
	if err != nil {
		return nil, err
	}
	out := make([]paperworkHistoryEntry, 0, len(rows))
	for _, row := range rows {
		id, err := valueAsInt64(row["id"])
		if err != nil {
			return nil, err
		}
		fileName, err := valueAsString(row["file_name"])
		if err != nil {
			return nil, err
		}
		fileMime, err := valueAsString(row["file_mime"])
		if err != nil {
			return nil, err
		}
		createdAtUnix, err := valueAsInt64(row["created_at"])
		if err != nil {
			return nil, err
		}
		out = append(out, paperworkHistoryEntry{
			ID:        id,
			FileName:  fileName,
			FileMime:  fileMime,
			CreatedAt: time.Unix(createdAtUnix, 0).UTC(),
		})
	}
	return out, nil
}

func (s *sqliteStore) getEmployeeI9HistoryFile(ctx context.Context, locationNumber, timePunchName string, versionID int64) ([]byte, string, string, error) {
	rows, err := s.query(ctx, `
		SELECT file_data, file_mime, file_name
		FROM employee_i9_form_history
		WHERE id = @id AND location_number = @location_number AND time_punch_name = @time_punch_name
		LIMIT 1;
	`, map[string]string{
		"id":              strconv.FormatInt(versionID, 10),
		"location_number": locationNumber,
		"time_punch_name": timePunchName,
	})
	if err != nil {
		return nil, "", "", err
	}
	if len(rows) == 0 {
		return nil, "", "", errNotFound
	}
	encoded, err := valueAsString(rows[0]["file_data"])
	if err != nil {
		return nil, "", "", err
	}
	if strings.TrimSpace(encoded) == "" {
		return nil, "", "", errNotFound
	}
	fileBytes, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, "", "", err
	}
	fileMime, _ := valueAsString(rows[0]["file_mime"])
	fileName, _ := valueAsString(rows[0]["file_name"])
	if strings.TrimSpace(fileMime) == "" {
		fileMime = "application/pdf"
	}
	return fileBytes, fileMime, fileName, nil
}

func (s *sqliteStore) addEmployeeI9Document(ctx context.Context, locationNumber, timePunchName, listType, documentTitle, issuingAuthority, documentNumber, expirationDate string, data []byte, mime, fileName string) error {
	encoded := base64.StdEncoding.EncodeToString(data)
	_, err := s.exec(ctx, `
		INSERT INTO employee_i9_documents (location_number, time_punch_name, list_type, document_title, issuing_authority, document_number, expiration_date, file_data, file_mime, file_name, created_at)
		VALUES (@location_number, @time_punch_name, @list_type, @document_title, @issuing_authority, @document_number, @expiration_date, @file_data, @file_mime, @file_name, @created_at);
	`, map[string]string{
		"location_number":   locationNumber,
		"time_punch_name":   timePunchName,
		"list_type":         strings.TrimSpace(strings.ToLower(listType)),
		"document_title":    strings.TrimSpace(documentTitle),
		"issuing_authority": strings.TrimSpace(issuingAuthority),
		"document_number":   strings.TrimSpace(documentNumber),
		"expiration_date":   strings.TrimSpace(expirationDate),
		"file_data":         encoded,
		"file_mime":         mime,
		"file_name":         fileName,
		"created_at":        strconv.FormatInt(time.Now().UTC().Unix(), 10),
	})
	return err
}

func (s *sqliteStore) listEmployeeI9Documents(ctx context.Context, locationNumber, timePunchName string) ([]employeeI9Document, error) {
	rows, err := s.query(ctx, `
		SELECT id, list_type, document_title, issuing_authority, document_number, expiration_date, file_name, file_mime, created_at
		FROM employee_i9_documents
		WHERE location_number = @location_number AND time_punch_name = @time_punch_name
		ORDER BY created_at DESC, id DESC;
	`, map[string]string{
		"location_number": locationNumber,
		"time_punch_name": timePunchName,
	})
	if err != nil {
		return nil, err
	}
	docs := make([]employeeI9Document, 0, len(rows))
	for _, row := range rows {
		id, err := valueAsInt64(row["id"])
		if err != nil {
			return nil, err
		}
		listType, err := valueAsString(row["list_type"])
		if err != nil {
			return nil, err
		}
		documentTitle, err := valueAsString(row["document_title"])
		if err != nil {
			return nil, err
		}
		issuingAuth, err := valueAsString(row["issuing_authority"])
		if err != nil {
			return nil, err
		}
		documentNumber, err := valueAsString(row["document_number"])
		if err != nil {
			return nil, err
		}
		expirationDate, err := valueAsString(row["expiration_date"])
		if err != nil {
			return nil, err
		}
		fileName, err := valueAsString(row["file_name"])
		if err != nil {
			return nil, err
		}
		fileMime, err := valueAsString(row["file_mime"])
		if err != nil {
			return nil, err
		}
		createdUnix, err := valueAsInt64(row["created_at"])
		if err != nil {
			return nil, err
		}
		docs = append(docs, employeeI9Document{
			ID:             id,
			LocationNumber: locationNumber,
			TimePunchName:  timePunchName,
			ListType:       listType,
			DocumentTitle:  documentTitle,
			IssuingAuth:    issuingAuth,
			DocumentNumber: documentNumber,
			ExpirationDate: expirationDate,
			FileName:       fileName,
			FileMime:       fileMime,
			CreatedAt:      time.Unix(createdUnix, 0).UTC(),
		})
	}
	return docs, nil
}

func (s *sqliteStore) getEmployeeI9DocumentFile(ctx context.Context, locationNumber, timePunchName string, docID int64) ([]byte, string, string, error) {
	rows, err := s.query(ctx, `
		SELECT file_data, file_mime, file_name
		FROM employee_i9_documents
		WHERE id = @id AND location_number = @location_number AND time_punch_name = @time_punch_name
		LIMIT 1;
	`, map[string]string{
		"id":              strconv.FormatInt(docID, 10),
		"location_number": locationNumber,
		"time_punch_name": timePunchName,
	})
	if err != nil {
		return nil, "", "", err
	}
	if len(rows) == 0 {
		return nil, "", "", errNotFound
	}
	encoded, err := valueAsString(rows[0]["file_data"])
	if err != nil {
		return nil, "", "", err
	}
	fileBytes, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, "", "", err
	}
	fileMime, _ := valueAsString(rows[0]["file_mime"])
	fileName, _ := valueAsString(rows[0]["file_name"])
	if strings.TrimSpace(fileMime) == "" {
		fileMime = http.DetectContentType(fileBytes)
	}
	return fileBytes, fileMime, fileName, nil
}

func (s *sqliteStore) deleteEmployeeI9Document(ctx context.Context, locationNumber, timePunchName string, docID int64) error {
	rows, err := s.query(ctx, `
		SELECT COUNT(*) AS count
		FROM employee_i9_documents
		WHERE id = @id AND location_number = @location_number AND time_punch_name = @time_punch_name;
	`, map[string]string{
		"id":              strconv.FormatInt(docID, 10),
		"location_number": locationNumber,
		"time_punch_name": timePunchName,
	})
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		return errNotFound
	}
	count, err := valueAsInt64(rows[0]["count"])
	if err != nil {
		return err
	}
	if count == 0 {
		return errNotFound
	}
	_, err = s.exec(ctx, `
		DELETE FROM employee_i9_documents
		WHERE id = @id AND location_number = @location_number AND time_punch_name = @time_punch_name;
	`, map[string]string{
		"id":              strconv.FormatInt(docID, 10),
		"location_number": locationNumber,
		"time_punch_name": timePunchName,
	})
	return err
}

func (s *sqliteStore) deleteEmployeeI9DocumentsForEmployee(ctx context.Context, locationNumber, timePunchName string) error {
	_, err := s.exec(ctx, `
		DELETE FROM employee_i9_documents
		WHERE location_number = @location_number
			AND time_punch_name = @time_punch_name;
	`, map[string]string{
		"location_number": locationNumber,
		"time_punch_name": timePunchName,
	})
	return err
}

func (s *sqliteStore) deleteEmployeeI9DocumentsByListType(ctx context.Context, locationNumber, timePunchName, listType string) error {
	_, err := s.exec(ctx, `
		DELETE FROM employee_i9_documents
		WHERE location_number = @location_number
			AND time_punch_name = @time_punch_name
			AND list_type = @list_type;
	`, map[string]string{
		"location_number": locationNumber,
		"time_punch_name": timePunchName,
		"list_type":       strings.TrimSpace(strings.ToLower(listType)),
	})
	return err
}

func (s *sqliteStore) getArchivedEmployeeI9Form(ctx context.Context, archivedEmployeeID int64) (employeeI9Form, error) {
	rows, err := s.query(ctx, `
		SELECT file_name, file_mime, updated_at, created_at
		FROM archived_employee_i9_forms
		WHERE archived_employee_id = @archived_employee_id
		LIMIT 1;
	`, map[string]string{
		"archived_employee_id": strconv.FormatInt(archivedEmployeeID, 10),
	})
	if err != nil {
		return employeeI9Form{}, err
	}
	if len(rows) == 0 {
		return employeeI9Form{HasFile: false}, nil
	}
	fileName, err := valueAsString(rows[0]["file_name"])
	if err != nil {
		return employeeI9Form{}, err
	}
	fileMime, err := valueAsString(rows[0]["file_mime"])
	if err != nil {
		return employeeI9Form{}, err
	}
	updatedUnix, err := valueAsInt64(rows[0]["updated_at"])
	if err != nil {
		return employeeI9Form{}, err
	}
	createdUnix, err := valueAsInt64(rows[0]["created_at"])
	if err != nil {
		return employeeI9Form{}, err
	}
	return employeeI9Form{
		FileName:  fileName,
		FileMime:  fileMime,
		UpdatedAt: time.Unix(updatedUnix, 0).UTC(),
		CreatedAt: time.Unix(createdUnix, 0).UTC(),
		HasFile:   true,
	}, nil
}

func (s *sqliteStore) getArchivedEmployeeI9File(ctx context.Context, archivedEmployeeID int64) ([]byte, string, string, error) {
	rows, err := s.query(ctx, `
		SELECT file_data, file_mime, file_name
		FROM archived_employee_i9_forms
		WHERE archived_employee_id = @archived_employee_id
		LIMIT 1;
	`, map[string]string{
		"archived_employee_id": strconv.FormatInt(archivedEmployeeID, 10),
	})
	if err != nil {
		return nil, "", "", err
	}
	if len(rows) == 0 {
		return nil, "", "", errNotFound
	}
	encoded, err := valueAsString(rows[0]["file_data"])
	if err != nil {
		return nil, "", "", err
	}
	if strings.TrimSpace(encoded) == "" {
		return nil, "", "", errNotFound
	}
	fileBytes, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, "", "", err
	}
	fileMime, _ := valueAsString(rows[0]["file_mime"])
	fileName, _ := valueAsString(rows[0]["file_name"])
	if strings.TrimSpace(fileMime) == "" {
		fileMime = "application/pdf"
	}
	return fileBytes, fileMime, fileName, nil
}

func (s *sqliteStore) listArchivedEmployeeI9Documents(ctx context.Context, archivedEmployeeID int64) ([]employeeI9Document, error) {
	rows, err := s.query(ctx, `
		SELECT id, list_type, document_title, issuing_authority, document_number, expiration_date, file_name, file_mime, created_at
		FROM archived_employee_i9_documents
		WHERE archived_employee_id = @archived_employee_id
		ORDER BY created_at DESC, id DESC;
	`, map[string]string{
		"archived_employee_id": strconv.FormatInt(archivedEmployeeID, 10),
	})
	if err != nil {
		return nil, err
	}
	docs := make([]employeeI9Document, 0, len(rows))
	for _, row := range rows {
		id, err := valueAsInt64(row["id"])
		if err != nil {
			return nil, err
		}
		listType, err := valueAsString(row["list_type"])
		if err != nil {
			return nil, err
		}
		documentTitle, err := valueAsString(row["document_title"])
		if err != nil {
			return nil, err
		}
		issuingAuth, err := valueAsString(row["issuing_authority"])
		if err != nil {
			return nil, err
		}
		documentNumber, err := valueAsString(row["document_number"])
		if err != nil {
			return nil, err
		}
		expirationDate, err := valueAsString(row["expiration_date"])
		if err != nil {
			return nil, err
		}
		fileName, err := valueAsString(row["file_name"])
		if err != nil {
			return nil, err
		}
		fileMime, err := valueAsString(row["file_mime"])
		if err != nil {
			return nil, err
		}
		createdUnix, err := valueAsInt64(row["created_at"])
		if err != nil {
			return nil, err
		}
		docs = append(docs, employeeI9Document{
			ID:             id,
			ListType:       listType,
			DocumentTitle:  documentTitle,
			IssuingAuth:    issuingAuth,
			DocumentNumber: documentNumber,
			ExpirationDate: expirationDate,
			FileName:       fileName,
			FileMime:       fileMime,
			CreatedAt:      time.Unix(createdUnix, 0).UTC(),
		})
	}
	return docs, nil
}

func (s *sqliteStore) getArchivedEmployeeI9DocumentFile(ctx context.Context, archivedEmployeeID, docID int64) ([]byte, string, string, error) {
	rows, err := s.query(ctx, `
		SELECT file_data, file_mime, file_name
		FROM archived_employee_i9_documents
		WHERE id = @id AND archived_employee_id = @archived_employee_id
		LIMIT 1;
	`, map[string]string{
		"id":                   strconv.FormatInt(docID, 10),
		"archived_employee_id": strconv.FormatInt(archivedEmployeeID, 10),
	})
	if err != nil {
		return nil, "", "", err
	}
	if len(rows) == 0 {
		return nil, "", "", errNotFound
	}
	encoded, err := valueAsString(rows[0]["file_data"])
	if err != nil {
		return nil, "", "", err
	}
	fileBytes, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, "", "", err
	}
	fileMime, _ := valueAsString(rows[0]["file_mime"])
	fileName, _ := valueAsString(rows[0]["file_name"])
	if strings.TrimSpace(fileMime) == "" {
		fileMime = http.DetectContentType(fileBytes)
	}
	return fileBytes, fileMime, fileName, nil
}

func (s *sqliteStore) upsertEmployeeW4Form(ctx context.Context, locationNumber, timePunchName string, data []byte, mime, fileName string) error {
	encoded := base64.StdEncoding.EncodeToString(data)
	now := time.Now().UTC().Unix()
	existingRows, err := s.query(ctx, `
		SELECT file_data, file_mime, file_name, updated_at
		FROM employee_w4_forms
		WHERE location_number = @location_number AND time_punch_name = @time_punch_name
		LIMIT 1;
	`, map[string]string{
		"location_number": locationNumber,
		"time_punch_name": timePunchName,
	})
	if err != nil {
		return err
	}
	if len(existingRows) > 0 {
		existingData, err := valueAsString(existingRows[0]["file_data"])
		if err != nil {
			return err
		}
		existingMime, err := valueAsString(existingRows[0]["file_mime"])
		if err != nil {
			return err
		}
		existingName, err := valueAsString(existingRows[0]["file_name"])
		if err != nil {
			return err
		}
		existingUpdatedAt, err := valueAsInt64(existingRows[0]["updated_at"])
		if err != nil {
			return err
		}
		if strings.TrimSpace(existingData) != "" {
			historyCreatedAt := now
			if existingUpdatedAt > 0 {
				historyCreatedAt = existingUpdatedAt
			}
			if _, err := s.exec(ctx, `
				INSERT INTO employee_w4_form_history (
					location_number, time_punch_name, file_data, file_mime, file_name, created_at
				)
				VALUES (
					@location_number, @time_punch_name, @file_data, @file_mime, @file_name, @created_at
				);
			`, map[string]string{
				"location_number": locationNumber,
				"time_punch_name": timePunchName,
				"file_data":       existingData,
				"file_mime":       existingMime,
				"file_name":       existingName,
				"created_at":      strconv.FormatInt(historyCreatedAt, 10),
			}); err != nil {
				return err
			}
		}
	}
	_, err = s.exec(ctx, `
		INSERT INTO employee_w4_forms (
			location_number, time_punch_name, file_data, file_mime, file_name, updated_at, created_at
		)
		VALUES (
			@location_number, @time_punch_name, @file_data, @file_mime, @file_name, @updated_at, @created_at
		)
		ON CONFLICT(location_number, time_punch_name)
		DO UPDATE SET
			file_data = excluded.file_data,
			file_mime = excluded.file_mime,
			file_name = excluded.file_name,
			updated_at = excluded.updated_at;
	`, map[string]string{
		"location_number": locationNumber,
		"time_punch_name": timePunchName,
		"file_data":       encoded,
		"file_mime":       mime,
		"file_name":       fileName,
		"updated_at":      strconv.FormatInt(now, 10),
		"created_at":      strconv.FormatInt(now, 10),
	})
	return err
}

func (s *sqliteStore) getEmployeeW4Form(ctx context.Context, locationNumber, timePunchName string) (employeeI9Form, error) {
	rows, err := s.query(ctx, `
		SELECT file_name, file_mime, updated_at, created_at
		FROM employee_w4_forms
		WHERE location_number = @location_number AND time_punch_name = @time_punch_name
		LIMIT 1;
	`, map[string]string{
		"location_number": locationNumber,
		"time_punch_name": timePunchName,
	})
	if err != nil {
		return employeeI9Form{}, err
	}
	if len(rows) == 0 {
		return employeeI9Form{
			LocationNumber: locationNumber,
			TimePunchName:  timePunchName,
			HasFile:        false,
		}, nil
	}
	fileName, err := valueAsString(rows[0]["file_name"])
	if err != nil {
		return employeeI9Form{}, err
	}
	fileMime, err := valueAsString(rows[0]["file_mime"])
	if err != nil {
		return employeeI9Form{}, err
	}
	updatedUnix, err := valueAsInt64(rows[0]["updated_at"])
	if err != nil {
		return employeeI9Form{}, err
	}
	createdUnix, err := valueAsInt64(rows[0]["created_at"])
	if err != nil {
		return employeeI9Form{}, err
	}
	return employeeI9Form{
		LocationNumber: locationNumber,
		TimePunchName:  timePunchName,
		FileName:       fileName,
		FileMime:       fileMime,
		UpdatedAt:      time.Unix(updatedUnix, 0).UTC(),
		CreatedAt:      time.Unix(createdUnix, 0).UTC(),
		HasFile:        true,
	}, nil
}

func (s *sqliteStore) getEmployeeW4File(ctx context.Context, locationNumber, timePunchName string) ([]byte, string, string, error) {
	rows, err := s.query(ctx, `
		SELECT file_data, file_mime, file_name
		FROM employee_w4_forms
		WHERE location_number = @location_number AND time_punch_name = @time_punch_name
		LIMIT 1;
	`, map[string]string{
		"location_number": locationNumber,
		"time_punch_name": timePunchName,
	})
	if err != nil {
		return nil, "", "", err
	}
	if len(rows) == 0 {
		return nil, "", "", errNotFound
	}
	encoded, err := valueAsString(rows[0]["file_data"])
	if err != nil {
		return nil, "", "", err
	}
	if strings.TrimSpace(encoded) == "" {
		return nil, "", "", errNotFound
	}
	fileBytes, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, "", "", err
	}
	fileMime, _ := valueAsString(rows[0]["file_mime"])
	fileName, _ := valueAsString(rows[0]["file_name"])
	if strings.TrimSpace(fileMime) == "" {
		fileMime = "application/pdf"
	}
	return fileBytes, fileMime, fileName, nil
}

func (s *sqliteStore) listEmployeeW4FormHistory(ctx context.Context, locationNumber, timePunchName string) ([]paperworkHistoryEntry, error) {
	rows, err := s.query(ctx, `
		SELECT id, file_name, file_mime, created_at
		FROM employee_w4_form_history
		WHERE location_number = @location_number AND time_punch_name = @time_punch_name
		ORDER BY created_at DESC, id DESC;
	`, map[string]string{
		"location_number": locationNumber,
		"time_punch_name": timePunchName,
	})
	if err != nil {
		return nil, err
	}
	out := make([]paperworkHistoryEntry, 0, len(rows))
	for _, row := range rows {
		id, err := valueAsInt64(row["id"])
		if err != nil {
			return nil, err
		}
		fileName, err := valueAsString(row["file_name"])
		if err != nil {
			return nil, err
		}
		fileMime, err := valueAsString(row["file_mime"])
		if err != nil {
			return nil, err
		}
		createdAtUnix, err := valueAsInt64(row["created_at"])
		if err != nil {
			return nil, err
		}
		out = append(out, paperworkHistoryEntry{
			ID:        id,
			FileName:  fileName,
			FileMime:  fileMime,
			CreatedAt: time.Unix(createdAtUnix, 0).UTC(),
		})
	}
	return out, nil
}

func (s *sqliteStore) getEmployeeW4HistoryFile(ctx context.Context, locationNumber, timePunchName string, versionID int64) ([]byte, string, string, error) {
	rows, err := s.query(ctx, `
		SELECT file_data, file_mime, file_name
		FROM employee_w4_form_history
		WHERE id = @id AND location_number = @location_number AND time_punch_name = @time_punch_name
		LIMIT 1;
	`, map[string]string{
		"id":              strconv.FormatInt(versionID, 10),
		"location_number": locationNumber,
		"time_punch_name": timePunchName,
	})
	if err != nil {
		return nil, "", "", err
	}
	if len(rows) == 0 {
		return nil, "", "", errNotFound
	}
	encoded, err := valueAsString(rows[0]["file_data"])
	if err != nil {
		return nil, "", "", err
	}
	if strings.TrimSpace(encoded) == "" {
		return nil, "", "", errNotFound
	}
	fileBytes, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, "", "", err
	}
	fileMime, _ := valueAsString(rows[0]["file_mime"])
	fileName, _ := valueAsString(rows[0]["file_name"])
	if strings.TrimSpace(fileMime) == "" {
		fileMime = "application/pdf"
	}
	return fileBytes, fileMime, fileName, nil
}

func (s *sqliteStore) getArchivedEmployeeW4Form(ctx context.Context, archivedEmployeeID int64) (employeeI9Form, error) {
	rows, err := s.query(ctx, `
		SELECT file_name, file_mime, updated_at, created_at
		FROM archived_employee_w4_forms
		WHERE archived_employee_id = @archived_employee_id
		LIMIT 1;
	`, map[string]string{
		"archived_employee_id": strconv.FormatInt(archivedEmployeeID, 10),
	})
	if err != nil {
		return employeeI9Form{}, err
	}
	if len(rows) == 0 {
		return employeeI9Form{HasFile: false}, nil
	}
	fileName, err := valueAsString(rows[0]["file_name"])
	if err != nil {
		return employeeI9Form{}, err
	}
	fileMime, err := valueAsString(rows[0]["file_mime"])
	if err != nil {
		return employeeI9Form{}, err
	}
	updatedUnix, err := valueAsInt64(rows[0]["updated_at"])
	if err != nil {
		return employeeI9Form{}, err
	}
	createdUnix, err := valueAsInt64(rows[0]["created_at"])
	if err != nil {
		return employeeI9Form{}, err
	}
	return employeeI9Form{
		FileName:  fileName,
		FileMime:  fileMime,
		UpdatedAt: time.Unix(updatedUnix, 0).UTC(),
		CreatedAt: time.Unix(createdUnix, 0).UTC(),
		HasFile:   true,
	}, nil
}

func (s *sqliteStore) getArchivedEmployeeW4File(ctx context.Context, archivedEmployeeID int64) ([]byte, string, string, error) {
	rows, err := s.query(ctx, `
		SELECT file_data, file_mime, file_name
		FROM archived_employee_w4_forms
		WHERE archived_employee_id = @archived_employee_id
		LIMIT 1;
	`, map[string]string{
		"archived_employee_id": strconv.FormatInt(archivedEmployeeID, 10),
	})
	if err != nil {
		return nil, "", "", err
	}
	if len(rows) == 0 {
		return nil, "", "", errNotFound
	}
	encoded, err := valueAsString(rows[0]["file_data"])
	if err != nil {
		return nil, "", "", err
	}
	if strings.TrimSpace(encoded) == "" {
		return nil, "", "", errNotFound
	}
	fileBytes, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, "", "", err
	}
	fileMime, _ := valueAsString(rows[0]["file_mime"])
	fileName, _ := valueAsString(rows[0]["file_name"])
	if strings.TrimSpace(fileMime) == "" {
		fileMime = "application/pdf"
	}
	return fileBytes, fileMime, fileName, nil
}

func (s *sqliteStore) upsertLocationEmployee(ctx context.Context, locationNumber string, emp employee) error {
	_, err := s.exec(ctx, `
		INSERT INTO location_employees (
			location_number, time_punch_name, employee_number, first_name, last_name, department, job_id, pay_type, pay_amount_cents, birthday, email, phone, address, apt_number, city, state, zip_code
		)
		VALUES (@location_number, @time_punch_name, @employee_number, @first_name, @last_name, @department, @job_id, @pay_type, @pay_amount_cents, @birthday, @email, @phone, @address, @apt_number, @city, @state, @zip_code)
		ON CONFLICT(location_number, time_punch_name)
		DO UPDATE SET
			employee_number = excluded.employee_number,
			first_name = excluded.first_name,
			last_name = excluded.last_name,
			department = excluded.department,
			job_id = excluded.job_id,
			pay_type = excluded.pay_type,
			pay_amount_cents = excluded.pay_amount_cents,
			birthday = excluded.birthday,
			email = excluded.email,
			phone = excluded.phone,
			address = excluded.address,
			apt_number = excluded.apt_number,
			city = excluded.city,
			state = excluded.state,
			zip_code = excluded.zip_code;
	`, map[string]string{
		"location_number":  locationNumber,
		"time_punch_name":  emp.TimePunchName,
		"employee_number":  strings.TrimSpace(emp.EmployeeNumber),
		"first_name":       emp.FirstName,
		"last_name":        emp.LastName,
		"department":       normalizeDepartment(emp.Department),
		"job_id":           strconv.FormatInt(emp.JobID, 10),
		"pay_type":         strings.TrimSpace(strings.ToLower(emp.PayType)),
		"pay_amount_cents": strconv.FormatInt(emp.PayAmountCents, 10),
		"birthday":         emp.Birthday,
		"email":            strings.TrimSpace(emp.Email),
		"phone":            strings.TrimSpace(emp.Phone),
		"address":          strings.TrimSpace(emp.Address),
		"apt_number":       strings.TrimSpace(emp.AptNumber),
		"city":             strings.TrimSpace(emp.City),
		"state":            strings.TrimSpace(emp.State),
		"zip_code":         strings.TrimSpace(emp.ZipCode),
	})
	return err
}

func (s *sqliteStore) updateLocationEmployeeDepartment(ctx context.Context, locationNumber, timePunchName, department string) error {
	if len(strings.TrimSpace(timePunchName)) == 0 {
		return errNotFound
	}
	rows, err := s.query(ctx, `
		SELECT COUNT(*) AS count
		FROM location_employees
		WHERE location_number = @location_number AND time_punch_name = @time_punch_name;
	`, map[string]string{
		"location_number": locationNumber,
		"time_punch_name": timePunchName,
	})
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		return errNotFound
	}
	count, err := valueAsInt64(rows[0]["count"])
	if err != nil {
		return err
	}
	if count == 0 {
		return errNotFound
	}

	_, err = s.exec(ctx, `
		UPDATE location_employees
		SET department = @department
		WHERE location_number = @location_number
			AND time_punch_name = @time_punch_name;
	`, map[string]string{
		"department":      normalizeDepartment(department),
		"location_number": locationNumber,
		"time_punch_name": timePunchName,
	})
	return err
}

func (s *sqliteStore) listLocationDepartments(ctx context.Context, locationNumber string) ([]locationDepartment, error) {
	rows, err := s.query(ctx, `
		SELECT id, location_number, name, created_at
		FROM location_departments
		WHERE location_number = @location_number
		ORDER BY name ASC, id ASC;
	`, map[string]string{"location_number": locationNumber})
	if err != nil {
		return nil, err
	}
	out := make([]locationDepartment, 0, len(rows))
	for _, row := range rows {
		id, err := valueAsInt64(row["id"])
		if err != nil {
			return nil, err
		}
		loc, err := valueAsString(row["location_number"])
		if err != nil {
			return nil, err
		}
		name, err := valueAsString(row["name"])
		if err != nil {
			return nil, err
		}
		createdAtUnix, err := valueAsInt64(row["created_at"])
		if err != nil {
			return nil, err
		}
		out = append(out, locationDepartment{
			ID:             id,
			LocationNumber: loc,
			Name:           strings.TrimSpace(name),
			CreatedAt:      time.Unix(createdAtUnix, 0).UTC(),
		})
	}
	return out, nil
}

func (s *sqliteStore) createLocationDepartment(ctx context.Context, locationNumber, name string) (locationDepartment, error) {
	now := time.Now().UTC()
	cleanName := strings.TrimSpace(name)
	if cleanName == "" {
		return locationDepartment{}, errors.New("department name is required")
	}
	_, err := s.exec(ctx, `
		INSERT INTO location_departments (location_number, name, created_at)
		VALUES (@location_number, @name, @created_at);
	`, map[string]string{
		"location_number": locationNumber,
		"name":            cleanName,
		"created_at":      strconv.FormatInt(now.Unix(), 10),
	})
	if err != nil {
		return locationDepartment{}, err
	}
	rows, err := s.query(ctx, `
		SELECT id, location_number, name, created_at
		FROM location_departments
		WHERE location_number = @location_number AND name = @name
		ORDER BY id DESC
		LIMIT 1;
	`, map[string]string{
		"location_number": locationNumber,
		"name":            cleanName,
	})
	if err != nil {
		return locationDepartment{}, err
	}
	if len(rows) == 0 {
		return locationDepartment{}, errNotFound
	}
	id, err := valueAsInt64(rows[0]["id"])
	if err != nil {
		return locationDepartment{}, err
	}
	createdAtUnix, err := valueAsInt64(rows[0]["created_at"])
	if err != nil {
		return locationDepartment{}, err
	}
	return locationDepartment{
		ID:             id,
		LocationNumber: locationNumber,
		Name:           cleanName,
		CreatedAt:      time.Unix(createdAtUnix, 0).UTC(),
	}, nil
}

func (s *sqliteStore) listLocationJobs(ctx context.Context, locationNumber string) ([]locationJob, error) {
	rows, err := s.query(ctx, `
		SELECT j.id, j.location_number, j.name, j.pay_type, j.pay_amount_cents, j.created_at
		FROM location_jobs j
		WHERE j.location_number = @location_number
		ORDER BY j.name ASC, j.id ASC;
	`, map[string]string{"location_number": locationNumber})
	if err != nil {
		return nil, err
	}
	out := make([]locationJob, 0, len(rows))
	for _, row := range rows {
		id, err := valueAsInt64(row["id"])
		if err != nil {
			return nil, err
		}
		loc, err := valueAsString(row["location_number"])
		if err != nil {
			return nil, err
		}
		payType, err := valueAsString(row["pay_type"])
		if err != nil {
			return nil, err
		}
		payAmountCents, err := valueAsInt64(row["pay_amount_cents"])
		if err != nil {
			return nil, err
		}
		name, err := valueAsString(row["name"])
		if err != nil {
			return nil, err
		}
		createdAtUnix, err := valueAsInt64(row["created_at"])
		if err != nil {
			return nil, err
		}
		job := locationJob{
			ID:              id,
			LocationNumber:  loc,
			DepartmentID:    0,
			DepartmentName:  "",
			DepartmentIDs:   []int64{},
			DepartmentNames: []string{},
			Name:            strings.TrimSpace(name),
			PayType:         strings.TrimSpace(payType),
			PayAmountCents:  payAmountCents,
			CreatedAt:       time.Unix(createdAtUnix, 0).UTC(),
		}
		out = append(out, job)
	}
	return out, nil
}

func (s *sqliteStore) getLocationJobByID(ctx context.Context, locationNumber string, jobID int64) (*locationJob, error) {
	rows, err := s.query(ctx, `
		SELECT j.id, j.location_number, j.name, j.pay_type, j.pay_amount_cents, j.created_at
		FROM location_jobs j
		WHERE j.location_number = @location_number AND j.id = @id
		LIMIT 1;
	`, map[string]string{
		"location_number": locationNumber,
		"id":              strconv.FormatInt(jobID, 10),
	})
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, errNotFound
	}
	name, err := valueAsString(rows[0]["name"])
	if err != nil {
		return nil, err
	}
	payType, err := valueAsString(rows[0]["pay_type"])
	if err != nil {
		return nil, err
	}
	payAmountCents, err := valueAsInt64(rows[0]["pay_amount_cents"])
	if err != nil {
		return nil, err
	}
	createdAtUnix, err := valueAsInt64(rows[0]["created_at"])
	if err != nil {
		return nil, err
	}
	job := &locationJob{
		ID:              jobID,
		LocationNumber:  locationNumber,
		DepartmentID:    0,
		DepartmentName:  "",
		DepartmentIDs:   []int64{},
		DepartmentNames: []string{},
		Name:            strings.TrimSpace(name),
		PayType:         strings.TrimSpace(payType),
		PayAmountCents:  payAmountCents,
		CreatedAt:       time.Unix(createdAtUnix, 0).UTC(),
	}
	return job, nil
}

func (s *sqliteStore) createLocationJob(ctx context.Context, locationNumber string, name, payType string, payAmountCents int64) (locationJob, error) {
	cleanName := strings.TrimSpace(name)
	if cleanName == "" {
		return locationJob{}, errors.New("job name is required")
	}
	payType = strings.ToLower(strings.TrimSpace(payType))
	if payType != "hourly" && payType != "salary" {
		return locationJob{}, errors.New("pay type must be hourly or salary")
	}
	if payAmountCents <= 0 {
		return locationJob{}, errors.New("pay amount must be greater than zero")
	}
	now := time.Now().UTC()
	_, err := s.exec(ctx, `
		INSERT INTO location_jobs (location_number, name, pay_type, pay_amount_cents, created_at)
		VALUES (@location_number, @name, @pay_type, @pay_amount_cents, @created_at);
	`, map[string]string{
		"location_number": locationNumber,
		"name":            cleanName,
		"pay_type":        payType,
		"pay_amount_cents": strconv.FormatInt(payAmountCents, 10),
		"created_at":      strconv.FormatInt(now.Unix(), 10),
	})
	if err != nil {
		return locationJob{}, err
	}
	jobRows, err := s.query(ctx, `
		SELECT id
		FROM location_jobs
		WHERE location_number = @location_number AND name = @name
		ORDER BY id DESC
		LIMIT 1;
	`, map[string]string{
		"location_number": locationNumber,
		"name":            cleanName,
	})
	if err != nil {
		return locationJob{}, err
	}
	if len(jobRows) == 0 {
		return locationJob{}, errNotFound
	}
	id, err := valueAsInt64(jobRows[0]["id"])
	if err != nil {
		return locationJob{}, err
	}
	job, err := s.getLocationJobByID(ctx, locationNumber, id)
	if err != nil {
		return locationJob{}, err
	}
	return *job, nil
}

func (s *sqliteStore) updateLocationJob(ctx context.Context, locationNumber string, jobID int64, name, payType string, payAmountCents int64) (*locationJob, error) {
	if _, err := s.getLocationJobByID(ctx, locationNumber, jobID); err != nil {
		return nil, err
	}
	cleanName := strings.TrimSpace(name)
	if cleanName == "" {
		return nil, errors.New("pay band name is required")
	}
	payType = strings.ToLower(strings.TrimSpace(payType))
	if payType != "hourly" && payType != "salary" {
		return nil, errors.New("pay type must be hourly or salary")
	}
	if payAmountCents <= 0 {
		return nil, errors.New("pay amount must be greater than zero")
	}
	_, err := s.exec(ctx, `
		UPDATE location_jobs
		SET name = @name,
			pay_type = @pay_type,
			pay_amount_cents = @pay_amount_cents
		WHERE id = @id AND location_number = @location_number;
	`, map[string]string{
		"id":               strconv.FormatInt(jobID, 10),
		"location_number":  locationNumber,
		"name":             cleanName,
		"pay_type":         payType,
		"pay_amount_cents": strconv.FormatInt(payAmountCents, 10),
	})
	if err != nil {
		return nil, err
	}
	return s.getLocationJobByID(ctx, locationNumber, jobID)
}

func (s *sqliteStore) assignLocationJobDepartments(ctx context.Context, locationNumber string, jobID int64, departmentIDs []int64) (locationJob, error) {
	if _, err := s.getLocationJobByID(ctx, locationNumber, jobID); err != nil {
		return locationJob{}, err
	}
	departments, err := s.listLocationDepartments(ctx, locationNumber)
	if err != nil {
		return locationJob{}, err
	}
	allowed := make(map[int64]struct{}, len(departments))
	for _, d := range departments {
		allowed[d.ID] = struct{}{}
	}
	cleanIDs := make([]int64, 0, len(departmentIDs))
	seen := make(map[int64]struct{}, len(departmentIDs))
	for _, id := range departmentIDs {
		if id <= 0 {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		if _, ok := allowed[id]; !ok {
			return locationJob{}, errors.New("invalid department")
		}
		seen[id] = struct{}{}
		cleanIDs = append(cleanIDs, id)
	}
	// Build a single atomic transaction: DELETE existing rows then INSERT new ones.
	// Integer values (jobID, department IDs) are embedded directly to avoid
	// FK type-coercion issues when bindSQLParams wraps them as text literals.
	nowUnix := time.Now().UTC().Unix()
	var sb strings.Builder
	sb.WriteString("BEGIN;\n")
	fmt.Fprintf(&sb, "DELETE FROM location_job_departments WHERE location_number = %s AND job_id = %d;\n",
		sqliteStringLiteral(locationNumber), jobID)
	for _, id := range cleanIDs {
		fmt.Fprintf(&sb, "INSERT INTO location_job_departments (location_number, job_id, department_id, created_at) VALUES (%s, %d, %d, %d);\n",
			sqliteStringLiteral(locationNumber), jobID, id, nowUnix)
	}
	sb.WriteString("COMMIT;\n")
	if _, err := s.exec(ctx, sb.String(), nil); err != nil {
		return locationJob{}, err
	}
	job, err := s.getLocationJobByID(ctx, locationNumber, jobID)
	if err != nil {
		return locationJob{}, err
	}
	return *job, nil
}

func (s *sqliteStore) updateLocationEmployeeJob(ctx context.Context, locationNumber, timePunchName string, jobID int64, departmentName, payType string, payAmountCents int64) error {
	if len(strings.TrimSpace(timePunchName)) == 0 {
		return errNotFound
	}
	rows, err := s.query(ctx, `
		SELECT COUNT(*) AS count
		FROM location_employees
		WHERE location_number = @location_number AND time_punch_name = @time_punch_name;
	`, map[string]string{
		"location_number": locationNumber,
		"time_punch_name": timePunchName,
	})
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		return errNotFound
	}
	count, err := valueAsInt64(rows[0]["count"])
	if err != nil {
		return err
	}
	if count == 0 {
		return errNotFound
	}
	_, err = s.exec(ctx, `
		UPDATE location_employees
		SET department = @department,
			job_id = @job_id,
			pay_type = @pay_type,
			pay_amount_cents = @pay_amount_cents
		WHERE location_number = @location_number
			AND time_punch_name = @time_punch_name;
	`, map[string]string{
		"department":      normalizeDepartment(departmentName),
		"job_id":          strconv.FormatInt(jobID, 10),
		"pay_type":        strings.TrimSpace(strings.ToLower(payType)),
		"pay_amount_cents": strconv.FormatInt(payAmountCents, 10),
		"location_number": locationNumber,
		"time_punch_name": timePunchName,
	})
	return err
}

func (s *sqliteStore) listEmployeeAdditionalCompensations(ctx context.Context, locationNumber, timePunchName string) ([]employeeAdditionalCompensation, error) {
	rows, err := s.query(ctx, `
		SELECT id, location_number, time_punch_name, label, amount_cents, created_at
		FROM employee_additional_compensations
		WHERE location_number = @location_number AND time_punch_name = @time_punch_name
		ORDER BY created_at DESC, id DESC;
	`, map[string]string{
		"location_number": locationNumber,
		"time_punch_name": timePunchName,
	})
	if err != nil {
		return nil, err
	}
	out := make([]employeeAdditionalCompensation, 0, len(rows))
	for _, row := range rows {
		id, err := valueAsInt64(row["id"])
		if err != nil {
			return nil, err
		}
		loc, err := valueAsString(row["location_number"])
		if err != nil {
			return nil, err
		}
		tpn, err := valueAsString(row["time_punch_name"])
		if err != nil {
			return nil, err
		}
		label, err := valueAsString(row["label"])
		if err != nil {
			return nil, err
		}
		amountCents, err := valueAsInt64(row["amount_cents"])
		if err != nil {
			return nil, err
		}
		createdAtUnix, err := valueAsInt64(row["created_at"])
		if err != nil {
			return nil, err
		}
		out = append(out, employeeAdditionalCompensation{
			ID:             id,
			LocationNumber: loc,
			TimePunchName:  tpn,
			Label:          strings.TrimSpace(label),
			AmountCents:    amountCents,
			CreatedAt:      time.Unix(createdAtUnix, 0).UTC(),
		})
	}
	return out, nil
}

func (s *sqliteStore) addEmployeeAdditionalCompensation(ctx context.Context, locationNumber, timePunchName, label string, amountCents int64) (*employeeAdditionalCompensation, error) {
	now := time.Now().UTC()
	_, err := s.exec(ctx, `
		INSERT INTO employee_additional_compensations (location_number, time_punch_name, label, amount_cents, created_at)
		VALUES (@location_number, @time_punch_name, @label, @amount_cents, @created_at);
	`, map[string]string{
		"location_number": locationNumber,
		"time_punch_name": timePunchName,
		"label":           strings.TrimSpace(label),
		"amount_cents":    strconv.FormatInt(amountCents, 10),
		"created_at":      strconv.FormatInt(now.Unix(), 10),
	})
	if err != nil {
		return nil, err
	}
	rows, err := s.query(ctx, `
		SELECT id, location_number, time_punch_name, label, amount_cents, created_at
		FROM employee_additional_compensations
		WHERE location_number = @location_number AND time_punch_name = @time_punch_name
		ORDER BY id DESC
		LIMIT 1;
	`, map[string]string{
		"location_number": locationNumber,
		"time_punch_name": timePunchName,
	})
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, errNotFound
	}
	id, err := valueAsInt64(rows[0]["id"])
	if err != nil {
		return nil, err
	}
	createdAtUnix, err := valueAsInt64(rows[0]["created_at"])
	if err != nil {
		return nil, err
	}
	labelValue, err := valueAsString(rows[0]["label"])
	if err != nil {
		return nil, err
	}
	amount, err := valueAsInt64(rows[0]["amount_cents"])
	if err != nil {
		return nil, err
	}
	return &employeeAdditionalCompensation{
		ID:             id,
		LocationNumber: locationNumber,
		TimePunchName:  timePunchName,
		Label:          strings.TrimSpace(labelValue),
		AmountCents:    amount,
		CreatedAt:      time.Unix(createdAtUnix, 0).UTC(),
	}, nil
}

func (s *sqliteStore) deleteEmployeeAdditionalCompensation(ctx context.Context, locationNumber, timePunchName string, compensationID int64) error {
	rows, err := s.query(ctx, `
		SELECT COUNT(*) AS count
		FROM employee_additional_compensations
		WHERE id = @id AND location_number = @location_number AND time_punch_name = @time_punch_name;
	`, map[string]string{
		"id":              strconv.FormatInt(compensationID, 10),
		"location_number": locationNumber,
		"time_punch_name": timePunchName,
	})
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		return errNotFound
	}
	count, err := valueAsInt64(rows[0]["count"])
	if err != nil {
		return err
	}
	if count == 0 {
		return errNotFound
	}
	_, err = s.exec(ctx, `
		DELETE FROM employee_additional_compensations
		WHERE id = @id AND location_number = @location_number AND time_punch_name = @time_punch_name;
	`, map[string]string{
		"id":              strconv.FormatInt(compensationID, 10),
		"location_number": locationNumber,
		"time_punch_name": timePunchName,
	})
	return err
}

func (s *sqliteStore) updateEmployeePhoto(ctx context.Context, locationNumber, timePunchName string, imageData []byte, mime string) error {
	if _, err := s.getLocationEmployee(ctx, locationNumber, timePunchName); err != nil {
		return err
	}
	encoded := base64.StdEncoding.EncodeToString(imageData)
	_, err := s.exec(ctx, `
		UPDATE location_employees
		SET profile_image_data = @profile_image_data,
			profile_image_mime = @profile_image_mime
		WHERE location_number = @location_number
			AND time_punch_name = @time_punch_name;
	`, map[string]string{
		"profile_image_data": encoded,
		"profile_image_mime": mime,
		"location_number":    locationNumber,
		"time_punch_name":    timePunchName,
	})
	return err
}

func (s *sqliteStore) getEmployeePhoto(ctx context.Context, locationNumber, timePunchName string) ([]byte, string, error) {
	rows, err := s.query(ctx, `
		SELECT profile_image_data, profile_image_mime
		FROM location_employees
		WHERE location_number = @location_number
			AND time_punch_name = @time_punch_name
		LIMIT 1;
	`, map[string]string{
		"location_number": locationNumber,
		"time_punch_name": timePunchName,
	})
	if err != nil {
		return nil, "", err
	}
	if len(rows) == 0 {
		return nil, "", errNotFound
	}
	dataEncoded, err := valueAsString(rows[0]["profile_image_data"])
	if err != nil {
		return nil, "", err
	}
	if strings.TrimSpace(dataEncoded) == "" {
		return nil, "", errNotFound
	}
	mime, err := valueAsString(rows[0]["profile_image_mime"])
	if err != nil {
		return nil, "", err
	}
	decoded, err := base64.StdEncoding.DecodeString(dataEncoded)
	if err != nil {
		return nil, "", err
	}
	if mime == "" {
		mime = "image/png"
	}
	return decoded, mime, nil
}

func (s *sqliteStore) createEmployeePhotoToken(ctx context.Context, token, locationNumber, timePunchName string, expiresAt time.Time) error {
	now := time.Now().UTC().Unix()
	_, err := s.exec(ctx, `
		INSERT INTO employee_photo_tokens (token, location_number, time_punch_name, expires_at, created_at)
		VALUES (@token, @location_number, @time_punch_name, @expires_at, @created_at);
	`, map[string]string{
		"token":           token,
		"location_number": locationNumber,
		"time_punch_name": timePunchName,
		"expires_at":      strconv.FormatInt(expiresAt.UTC().Unix(), 10),
		"created_at":      strconv.FormatInt(now, 10),
	})
	return err
}

func (s *sqliteStore) getEmployeePhotoToken(ctx context.Context, token string) (*employeePhotoToken, error) {
	rows, err := s.query(ctx, `
		SELECT token, location_number, time_punch_name, expires_at, used_at
		FROM employee_photo_tokens
		WHERE token = @token
		LIMIT 1;
	`, map[string]string{"token": token})
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, errNotFound
	}
	locationNumber, err := valueAsString(rows[0]["location_number"])
	if err != nil {
		return nil, err
	}
	timePunchName, err := valueAsString(rows[0]["time_punch_name"])
	if err != nil {
		return nil, err
	}
	expiresUnix, err := valueAsInt64(rows[0]["expires_at"])
	if err != nil {
		return nil, err
	}
	expiresAt := time.Unix(expiresUnix, 0).UTC()
	if time.Now().UTC().After(expiresAt) {
		return nil, errNotFound
	}
	var usedAt *time.Time
	switch raw := rows[0]["used_at"].(type) {
	case nil:
	case float64:
		v := time.Unix(int64(raw), 0).UTC()
		usedAt = &v
	}
	if usedAt != nil {
		return nil, errNotFound
	}
	return &employeePhotoToken{
		Token:         token,
		LocationNum:   locationNumber,
		TimePunchName: timePunchName,
		ExpiresAt:     expiresAt,
		UsedAt:        usedAt,
	}, nil
}

func (s *sqliteStore) markEmployeePhotoTokenUsed(ctx context.Context, token string) error {
	_, err := s.exec(ctx, `
		UPDATE employee_photo_tokens
		SET used_at = @used_at
		WHERE token = @token;
	`, map[string]string{
		"token":   token,
		"used_at": strconv.FormatInt(time.Now().UTC().Unix(), 10),
	})
	return err
}

func (s *sqliteStore) getEmployeePaperworkToken(ctx context.Context, token string) (*employeePaperworkToken, error) {
	rows, err := s.query(ctx, `
		SELECT token, location_number, time_punch_name, expires_at
		FROM employee_paperwork_tokens
		WHERE token = @token
		LIMIT 1;
	`, map[string]string{"token": token})
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, errNotFound
	}
	locationNumber, err := valueAsString(rows[0]["location_number"])
	if err != nil {
		return nil, err
	}
	timePunchName, err := valueAsString(rows[0]["time_punch_name"])
	if err != nil {
		return nil, err
	}
	expiresUnix, err := valueAsInt64(rows[0]["expires_at"])
	if err != nil {
		return nil, err
	}
	expiresAt := time.Unix(expiresUnix, 0).UTC()
	if time.Now().UTC().After(expiresAt) {
		return nil, errNotFound
	}
	return &employeePaperworkToken{
		Token:         token,
		LocationNum:   locationNumber,
		TimePunchName: timePunchName,
		ExpiresAt:     expiresAt,
	}, nil
}

func (s *sqliteStore) getOrCreateEmployeePaperworkToken(ctx context.Context, locationNumber, timePunchName string) (string, error) {
	token, err := randomToken(32)
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()
	expiresAt := now.Add(7 * 24 * time.Hour)
	_, err = s.exec(ctx, `
		INSERT INTO employee_paperwork_tokens (token, location_number, time_punch_name, expires_at, created_at)
		VALUES (@token, @location_number, @time_punch_name, @expires_at, @created_at)
		ON CONFLICT(location_number, time_punch_name)
		DO UPDATE SET
			token = excluded.token,
			expires_at = excluded.expires_at,
			created_at = excluded.created_at;
	`, map[string]string{
		"token":           token,
		"location_number": locationNumber,
		"time_punch_name": timePunchName,
		"expires_at":      strconv.FormatInt(expiresAt.Unix(), 10),
		"created_at":      strconv.FormatInt(now.Unix(), 10),
	})
	if err != nil {
		return "", err
	}
	return token, nil
}

func (s *sqliteStore) createCandidateInterviewToken(ctx context.Context, token candidateInterviewToken) error {
	now := time.Now().UTC().Unix()
	_, err := s.exec(ctx, `
		INSERT INTO location_candidate_interview_tokens (token, location_number, candidate_id, interviewer_time_punch_name, interview_type, scheduled_at, expires_at, used_at, created_at)
		VALUES (@token, @location_number, @candidate_id, @interviewer_time_punch_name, @interview_type, @scheduled_at, @expires_at, 0, @created_at);
	`, map[string]string{
		"token":                       token.Token,
		"location_number":             token.LocationNumber,
		"candidate_id":                strconv.FormatInt(token.CandidateID, 10),
		"interviewer_time_punch_name": strings.TrimSpace(token.InterviewerTimePunchName),
		"interview_type":              strings.TrimSpace(token.InterviewType),
		"scheduled_at":                strconv.FormatInt(token.ScheduledAt.UTC().Unix(), 10),
		"expires_at":                  strconv.FormatInt(token.ExpiresAt.UTC().Unix(), 10),
		"created_at":                  strconv.FormatInt(now, 10),
	})
	return err
}

func (s *sqliteStore) getCandidateInterviewToken(ctx context.Context, token string) (*candidateInterviewToken, error) {
	rows, err := s.query(ctx, `
		SELECT token, location_number, candidate_id, interviewer_time_punch_name, interview_type, scheduled_at, expires_at, used_at
		FROM location_candidate_interview_tokens
		WHERE token = @token
		LIMIT 1;
	`, map[string]string{"token": token})
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, errNotFound
	}
	locationNumber, err := valueAsString(rows[0]["location_number"])
	if err != nil {
		return nil, err
	}
	candidateID, err := valueAsInt64(rows[0]["candidate_id"])
	if err != nil {
		return nil, err
	}
	interviewerTPN, err := valueAsString(rows[0]["interviewer_time_punch_name"])
	if err != nil {
		return nil, err
	}
	interviewType, err := valueAsString(rows[0]["interview_type"])
	if err != nil {
		return nil, err
	}
	scheduledUnix, err := valueAsInt64(rows[0]["scheduled_at"])
	if err != nil {
		return nil, err
	}
	expiresUnix, err := valueAsInt64(rows[0]["expires_at"])
	if err != nil {
		return nil, err
	}
	expiresAt := time.Unix(expiresUnix, 0).UTC()
	usedUnix, err := valueAsInt64(rows[0]["used_at"])
	if err != nil {
		return nil, err
	}
	if usedUnix > 0 {
		return nil, errNotFound
	}
	return &candidateInterviewToken{
		Token:                    token,
		LocationNumber:           locationNumber,
		CandidateID:              candidateID,
		InterviewerTimePunchName: interviewerTPN,
		InterviewType:            interviewType,
		ScheduledAt:              time.Unix(scheduledUnix, 0).UTC(),
		ExpiresAt:                expiresAt,
	}, nil
}

func (s *sqliteStore) deleteCandidateInterviewLink(ctx context.Context, locationNumber string, candidateID int64, token string) error {
	rows, err := s.query(ctx, `
		SELECT COUNT(*) AS count
		FROM location_candidate_interview_tokens
		WHERE token = @token AND location_number = @location_number AND candidate_id = @candidate_id;
	`, map[string]string{
		"token":           token,
		"location_number": locationNumber,
		"candidate_id":    strconv.FormatInt(candidateID, 10),
	})
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		return errNotFound
	}
	count, err := valueAsInt64(rows[0]["count"])
	if err != nil {
		return err
	}
	if count == 0 {
		return errNotFound
	}
	_, err = s.exec(ctx, `
		DELETE FROM location_candidate_interview_tokens
		WHERE token = @token AND location_number = @location_number AND candidate_id = @candidate_id;
	`, map[string]string{
		"token":           token,
		"location_number": locationNumber,
		"candidate_id":    strconv.FormatInt(candidateID, 10),
	})
	return err
}

func (s *sqliteStore) markCandidateInterviewTokenUsed(ctx context.Context, token string) error {
	_, err := s.exec(ctx, `
		UPDATE location_candidate_interview_tokens
		SET used_at = @used_at
		WHERE token = @token;
	`, map[string]string{
		"token":   token,
		"used_at": strconv.FormatInt(time.Now().UTC().Unix(), 10),
	})
	return err
}

func (s *sqliteStore) listCandidateInterviewLinks(ctx context.Context, locationNumber string, candidateID int64) ([]candidateInterviewLink, error) {
	rows, err := s.query(ctx, `
		SELECT token, location_number, candidate_id, interviewer_time_punch_name, interview_type, scheduled_at, expires_at, used_at, created_at
		FROM location_candidate_interview_tokens
		WHERE location_number = @location_number AND candidate_id = @candidate_id
		ORDER BY scheduled_at DESC, created_at DESC;
	`, map[string]string{
		"location_number": locationNumber,
		"candidate_id":    strconv.FormatInt(candidateID, 10),
	})
	if err != nil {
		return nil, err
	}
	out := make([]candidateInterviewLink, 0, len(rows))
	for _, row := range rows {
		token, err := valueAsString(row["token"])
		if err != nil {
			return nil, err
		}
		loc, err := valueAsString(row["location_number"])
		if err != nil {
			return nil, err
		}
		cid, err := valueAsInt64(row["candidate_id"])
		if err != nil {
			return nil, err
		}
		interviewer, err := valueAsString(row["interviewer_time_punch_name"])
		if err != nil {
			return nil, err
		}
		itype, err := valueAsString(row["interview_type"])
		if err != nil {
			return nil, err
		}
		scheduledUnix, err := valueAsInt64(row["scheduled_at"])
		if err != nil {
			return nil, err
		}
		expiresUnix, err := valueAsInt64(row["expires_at"])
		if err != nil {
			return nil, err
		}
		createdUnix, err := valueAsInt64(row["created_at"])
		if err != nil {
			return nil, err
		}
		usedUnix := int64(0)
		if rawUsed, ok := row["used_at"]; ok && rawUsed != nil {
			usedUnix, err = valueAsInt64(rawUsed)
			if err != nil {
				return nil, err
			}
		}
		record := candidateInterviewLink{
			Token:                    token,
			LocationNumber:           loc,
			CandidateID:              cid,
			InterviewerTimePunchName: interviewer,
			InterviewType:            itype,
			ScheduledAt:              time.Unix(scheduledUnix, 0).UTC(),
			Link:                     "/interview/" + token,
			ExpiresAt:                time.Unix(expiresUnix, 0).UTC(),
			CreatedAt:                time.Unix(createdUnix, 0).UTC(),
		}
		if usedUnix > 0 {
			usedAt := time.Unix(usedUnix, 0).UTC()
			record.UsedAt = &usedAt
		}
		out = append(out, record)
	}
	return out, nil
}

func (s *sqliteStore) listLocationInterviewCalendar(ctx context.Context, locationNumber string) ([]interviewCalendarEntry, error) {
	rows, err := s.query(ctx, `
		SELECT
			t.token,
			t.location_number,
			t.candidate_id,
			c.first_name,
			c.last_name,
			t.interviewer_time_punch_name,
			t.interview_type,
			t.scheduled_at,
			t.used_at,
			t.created_at
		FROM location_candidate_interview_tokens t
		INNER JOIN location_candidates c ON c.id = t.candidate_id AND c.location_number = t.location_number
		WHERE t.location_number = @location_number
			AND t.used_at = 0
		ORDER BY t.scheduled_at ASC, t.created_at ASC;
	`, map[string]string{
		"location_number": locationNumber,
	})
	if err != nil {
		return nil, err
	}
	out := make([]interviewCalendarEntry, 0, len(rows))
	for _, row := range rows {
		token, err := valueAsString(row["token"])
		if err != nil {
			return nil, err
		}
		loc, err := valueAsString(row["location_number"])
		if err != nil {
			return nil, err
		}
		candidateID, err := valueAsInt64(row["candidate_id"])
		if err != nil {
			return nil, err
		}
		firstName, err := valueAsString(row["first_name"])
		if err != nil {
			return nil, err
		}
		lastName, err := valueAsString(row["last_name"])
		if err != nil {
			return nil, err
		}
		interviewer, err := valueAsString(row["interviewer_time_punch_name"])
		if err != nil {
			return nil, err
		}
		interviewType, err := valueAsString(row["interview_type"])
		if err != nil {
			return nil, err
		}
		scheduledUnix, err := valueAsInt64(row["scheduled_at"])
		if err != nil {
			return nil, err
		}
		createdUnix, err := valueAsInt64(row["created_at"])
		if err != nil {
			return nil, err
		}
		usedUnix := int64(0)
		if rawUsed, ok := row["used_at"]; ok && rawUsed != nil {
			usedUnix, err = valueAsInt64(rawUsed)
			if err != nil {
				return nil, err
			}
		}
		entry := interviewCalendarEntry{
			Token:                    token,
			LocationNumber:           loc,
			CandidateID:              candidateID,
			CandidateFirstName:       firstName,
			CandidateLastName:        lastName,
			InterviewerTimePunchName: interviewer,
			InterviewType:            interviewType,
			ScheduledAt:              time.Unix(scheduledUnix, 0).UTC(),
			CreatedAt:                time.Unix(createdUnix, 0).UTC(),
		}
		if usedUnix > 0 {
			usedAt := time.Unix(usedUnix, 0).UTC()
			entry.UsedAt = &usedAt
		}
		out = append(out, entry)
	}
	return out, nil
}

func (s *sqliteStore) getCandidateInterviewLink(ctx context.Context, locationNumber string, candidateID int64, token string) (*candidateInterviewLink, error) {
	rows, err := s.query(ctx, `
		SELECT token, location_number, candidate_id, interviewer_time_punch_name, interview_type, scheduled_at, expires_at, used_at, created_at
		FROM location_candidate_interview_tokens
		WHERE token = @token AND location_number = @location_number AND candidate_id = @candidate_id
		LIMIT 1;
	`, map[string]string{
		"token":           token,
		"location_number": locationNumber,
		"candidate_id":    strconv.FormatInt(candidateID, 10),
	})
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, errNotFound
	}
	list, err := s.listCandidateInterviewLinks(ctx, locationNumber, candidateID)
	if err != nil {
		return nil, err
	}
	for i := range list {
		if list[i].Token == token {
			return &list[i], nil
		}
	}
	return nil, errNotFound
}

func (s *sqliteStore) getLocationTimePunchToken(ctx context.Context, token string) (*locationTimePunchToken, error) {
	rows, err := s.query(ctx, `
		SELECT token, location_number
		FROM location_time_punch_tokens
		WHERE token = @token
		LIMIT 1;
	`, map[string]string{"token": token})
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, errNotFound
	}
	locationNumber, err := valueAsString(rows[0]["location_number"])
	if err != nil {
		return nil, err
	}
	return &locationTimePunchToken{
		Token:          token,
		LocationNumber: locationNumber,
	}, nil
}

func (s *sqliteStore) getOrCreateLocationTimePunchToken(ctx context.Context, locationNumber string) (string, error) {
	rows, err := s.query(ctx, `
		SELECT token
		FROM location_time_punch_tokens
		WHERE location_number = @location_number
		LIMIT 1;
	`, map[string]string{"location_number": locationNumber})
	if err != nil {
		return "", err
	}
	if len(rows) > 0 {
		token, err := valueAsString(rows[0]["token"])
		if err != nil {
			return "", err
		}
		if strings.TrimSpace(token) != "" {
			return token, nil
		}
	}

	token, err := randomToken(32)
	if err != nil {
		return "", err
	}
	_, err = s.exec(ctx, `
		INSERT INTO location_time_punch_tokens (token, location_number, created_at)
		VALUES (@token, @location_number, @created_at)
		ON CONFLICT(location_number)
		DO UPDATE SET token = excluded.token;
	`, map[string]string{
		"token":           token,
		"location_number": locationNumber,
		"created_at":      strconv.FormatInt(time.Now().UTC().Unix(), 10),
	})
	if err != nil {
		return "", err
	}
	return token, nil
}

func (s *sqliteStore) getLocationTimeOffToken(ctx context.Context, token string) (*locationTimeOffToken, error) {
	rows, err := s.query(ctx, `
		SELECT token, location_number
		FROM location_time_off_tokens
		WHERE token = @token
		LIMIT 1;
	`, map[string]string{"token": token})
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, errNotFound
	}
	locationNumber, err := valueAsString(rows[0]["location_number"])
	if err != nil {
		return nil, err
	}
	return &locationTimeOffToken{
		Token:          token,
		LocationNumber: locationNumber,
	}, nil
}

func (s *sqliteStore) getOrCreateLocationTimeOffToken(ctx context.Context, locationNumber string) (string, error) {
	rows, err := s.query(ctx, `
		SELECT token
		FROM location_time_off_tokens
		WHERE location_number = @location_number
		LIMIT 1;
	`, map[string]string{"location_number": locationNumber})
	if err != nil {
		return "", err
	}
	if len(rows) > 0 {
		token, err := valueAsString(rows[0]["token"])
		if err != nil {
			return "", err
		}
		if strings.TrimSpace(token) != "" {
			return token, nil
		}
	}
	token, err := randomToken(32)
	if err != nil {
		return "", err
	}
	_, err = s.exec(ctx, `
		INSERT INTO location_time_off_tokens (token, location_number, created_at)
		VALUES (@token, @location_number, @created_at)
		ON CONFLICT(location_number)
		DO UPDATE SET token = excluded.token;
	`, map[string]string{
		"token":           token,
		"location_number": locationNumber,
		"created_at":      strconv.FormatInt(time.Now().UTC().Unix(), 10),
	})
	if err != nil {
		return "", err
	}
	return token, nil
}

func (s *sqliteStore) createTimeOffRequest(ctx context.Context, req timeOffRequest) error {
	_, err := s.exec(ctx, `
		INSERT INTO location_time_off_requests (
			location_number, time_punch_name, start_date, end_date, created_at
		)
		VALUES (@location_number, @time_punch_name, @start_date, @end_date, @created_at);
	`, map[string]string{
		"location_number": req.LocationNum,
		"time_punch_name": req.TimePunchName,
		"start_date":      req.StartDate,
		"end_date":        req.EndDate,
		"created_at":      strconv.FormatInt(req.CreatedAt.UTC().Unix(), 10),
	})
	return err
}

func (s *sqliteStore) listTimeOffRequests(ctx context.Context, locationNumber string, archived bool) ([]timeOffRequest, error) {
	archivedFilter := "archived_at = 0"
	if archived {
		archivedFilter = "archived_at > 0"
	}
	rows, err := s.query(ctx, `
		SELECT id, location_number, time_punch_name, start_date, end_date, archived_at, created_at
		FROM location_time_off_requests
		WHERE location_number = @location_number
			AND `+archivedFilter+`
		ORDER BY created_at DESC, id DESC;
	`, map[string]string{"location_number": locationNumber})
	if err != nil {
		return nil, err
	}
	out := make([]timeOffRequest, 0, len(rows))
	for _, row := range rows {
		id, err := valueAsInt64(row["id"])
		if err != nil {
			return nil, err
		}
		locNum, err := valueAsString(row["location_number"])
		if err != nil {
			return nil, err
		}
		timePunchName, err := valueAsString(row["time_punch_name"])
		if err != nil {
			return nil, err
		}
		startDate, err := valueAsString(row["start_date"])
		if err != nil {
			return nil, err
		}
		endDate, err := valueAsString(row["end_date"])
		if err != nil {
			return nil, err
		}
		archivedAtUnix, err := valueAsInt64(row["archived_at"])
		if err != nil {
			return nil, err
		}
		createdAtUnix, err := valueAsInt64(row["created_at"])
		if err != nil {
			return nil, err
		}
		archivedAt := time.Time{}
		if archivedAtUnix > 0 {
			archivedAt = time.Unix(archivedAtUnix, 0).UTC()
		}
		out = append(out, timeOffRequest{
			ID:            id,
			LocationNum:   locNum,
			TimePunchName: timePunchName,
			StartDate:     startDate,
			EndDate:       endDate,
			CreatedAt:     time.Unix(createdAtUnix, 0).UTC(),
			ArchivedAt:    archivedAt,
		})
	}
	return out, nil
}

func (s *sqliteStore) archiveTimeOffRequest(ctx context.Context, locationNumber string, requestID int64) error {
	rows, err := s.query(ctx, `
		SELECT COUNT(*) AS count
		FROM location_time_off_requests
		WHERE id = @id
			AND location_number = @location_number
			AND archived_at = 0;
	`, map[string]string{
		"id":              strconv.FormatInt(requestID, 10),
		"location_number": locationNumber,
	})
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		return errNotFound
	}
	count, err := valueAsInt64(rows[0]["count"])
	if err != nil {
		return err
	}
	if count == 0 {
		return errNotFound
	}
	_, err = s.exec(ctx, `
		UPDATE location_time_off_requests
		SET archived_at = @archived_at
		WHERE id = @id
			AND location_number = @location_number
			AND archived_at = 0;
	`, map[string]string{
		"id":              strconv.FormatInt(requestID, 10),
		"location_number": locationNumber,
		"archived_at":     strconv.FormatInt(time.Now().UTC().Unix(), 10),
	})
	return err
}

func (s *sqliteStore) createTimePunchEntry(ctx context.Context, entry timePunchEntry) error {
	_, err := s.exec(ctx, `
		INSERT INTO location_time_punch_entries (
			location_number, time_punch_name, punch_date, time_in, time_out, note, forgot_break_clock_in_return, created_at
		)
		VALUES (@location_number, @time_punch_name, @punch_date, @time_in, @time_out, @note, @forgot_break_clock_in_return, @created_at);
	`, map[string]string{
		"location_number":              entry.LocationNum,
		"time_punch_name":              entry.TimePunchName,
		"punch_date":                   entry.PunchDate,
		"time_in":                      entry.TimeIn,
		"time_out":                     entry.TimeOut,
		"note":                         entry.Note,
		"forgot_break_clock_in_return": strconv.FormatInt(boolToInt64(entry.ForgotBreakClockInReturn), 10),
		"created_at":                   strconv.FormatInt(entry.CreatedAt.UTC().Unix(), 10),
	})
	return err
}

func (s *sqliteStore) listTimePunchEntries(ctx context.Context, locationNumber string, archived bool) ([]timePunchEntry, error) {
	archivedFilter := "archived_at = 0"
	if archived {
		archivedFilter = "archived_at > 0"
	}
	rows, err := s.query(ctx, `
		SELECT id, location_number, time_punch_name, punch_date, time_in, time_out, note, forgot_break_clock_in_return, archived_at, created_at
		FROM location_time_punch_entries
		WHERE location_number = @location_number
			AND `+archivedFilter+`
		ORDER BY created_at DESC, id DESC;
	`, map[string]string{"location_number": locationNumber})
	if err != nil {
		return nil, err
	}
	out := make([]timePunchEntry, 0, len(rows))
	for _, row := range rows {
		id, err := valueAsInt64(row["id"])
		if err != nil {
			return nil, err
		}
		locNum, err := valueAsString(row["location_number"])
		if err != nil {
			return nil, err
		}
		timePunchName, err := valueAsString(row["time_punch_name"])
		if err != nil {
			return nil, err
		}
		punchDate, err := valueAsString(row["punch_date"])
		if err != nil {
			return nil, err
		}
		timeIn, err := valueAsString(row["time_in"])
		if err != nil {
			return nil, err
		}
		timeOut, err := valueAsString(row["time_out"])
		if err != nil {
			return nil, err
		}
		note, err := valueAsString(row["note"])
		if err != nil {
			return nil, err
		}
		forgotBreakClockInReturnInt, err := valueAsInt64(row["forgot_break_clock_in_return"])
		if err != nil {
			return nil, err
		}
		archivedAtUnix, err := valueAsInt64(row["archived_at"])
		if err != nil {
			return nil, err
		}
		createdAtUnix, err := valueAsInt64(row["created_at"])
		if err != nil {
			return nil, err
		}
		archivedAt := time.Time{}
		if archivedAtUnix > 0 {
			archivedAt = time.Unix(archivedAtUnix, 0).UTC()
		}
		out = append(out, timePunchEntry{
			ID:                       id,
			LocationNum:              locNum,
			TimePunchName:            timePunchName,
			PunchDate:                punchDate,
			TimeIn:                   timeIn,
			TimeOut:                  timeOut,
			Note:                     note,
			ForgotBreakClockInReturn: forgotBreakClockInReturnInt > 0,
			ArchivedAt:               archivedAt,
			CreatedAt:                time.Unix(createdAtUnix, 0).UTC(),
		})
	}
	return out, nil
}

func (s *sqliteStore) archiveTimePunchEntry(ctx context.Context, locationNumber string, entryID int64) error {
	rows, err := s.query(ctx, `
		SELECT COUNT(*) AS count
		FROM location_time_punch_entries
		WHERE id = @id
			AND location_number = @location_number
			AND archived_at = 0;
	`, map[string]string{
		"id":              strconv.FormatInt(entryID, 10),
		"location_number": locationNumber,
	})
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		return errNotFound
	}
	count, err := valueAsInt64(rows[0]["count"])
	if err != nil {
		return err
	}
	if count == 0 {
		return errNotFound
	}
	_, err = s.exec(ctx, `
		UPDATE location_time_punch_entries
		SET archived_at = @archived_at
		WHERE id = @id
			AND location_number = @location_number
			AND archived_at = 0;
	`, map[string]string{
		"id":              strconv.FormatInt(entryID, 10),
		"location_number": locationNumber,
		"archived_at":     strconv.FormatInt(time.Now().UTC().Unix(), 10),
	})
	return err
}

func (s *sqliteStore) deleteTimePunchEntry(ctx context.Context, locationNumber string, entryID int64) error {
	rows, err := s.query(ctx, `
		SELECT COUNT(*) AS count
		FROM location_time_punch_entries
		WHERE id = @id AND location_number = @location_number;
	`, map[string]string{
		"id":              strconv.FormatInt(entryID, 10),
		"location_number": locationNumber,
	})
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		return errNotFound
	}
	count, err := valueAsInt64(rows[0]["count"])
	if err != nil {
		return err
	}
	if count == 0 {
		return errNotFound
	}
	_, err = s.exec(ctx, `
		DELETE FROM location_time_punch_entries
		WHERE id = @id AND location_number = @location_number;
	`, map[string]string{
		"id":              strconv.FormatInt(entryID, 10),
		"location_number": locationNumber,
	})
	return err
}

func (s *sqliteStore) upsertBusinessDay(ctx context.Context, day businessDay) error {
	_, err := s.exec(ctx, `
		INSERT INTO location_business_days (
			location_number, business_date, total_sales, labor_hours, created_at, updated_at
		)
		VALUES (@location_number, @business_date, @total_sales, @labor_hours, @created_at, @updated_at)
		ON CONFLICT(location_number, business_date)
		DO UPDATE SET
			total_sales = excluded.total_sales,
			labor_hours = excluded.labor_hours,
			updated_at = excluded.updated_at;
	`, map[string]string{
		"location_number": day.LocationNum,
		"business_date":   day.BusinessDate,
		"total_sales":     strconv.FormatFloat(day.TotalSales, 'f', -1, 64),
		"labor_hours":     strconv.FormatFloat(day.LaborHours, 'f', -1, 64),
		"created_at":      strconv.FormatInt(day.CreatedAt.UTC().Unix(), 10),
		"updated_at":      strconv.FormatInt(day.UpdatedAt.UTC().Unix(), 10),
	})
	return err
}

func (s *sqliteStore) findExistingBusinessDates(ctx context.Context, locationNumber string, dates []string) ([]string, error) {
	if len(dates) == 0 {
		return []string{}, nil
	}
	values := make([]string, 0, len(dates))
	for _, date := range dates {
		values = append(values, sqliteStringLiteral(strings.TrimSpace(date)))
	}
	statement := `
		SELECT business_date
		FROM location_business_days
		WHERE location_number = @location_number
			AND business_date IN (` + strings.Join(values, ", ") + `)
		ORDER BY business_date ASC;
	`
	rows, err := s.query(ctx, statement, map[string]string{
		"location_number": locationNumber,
	})
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(rows))
	for _, row := range rows {
		value, err := valueAsString(row["business_date"])
		if err != nil {
			return nil, err
		}
		out = append(out, value)
	}
	return out, nil
}

func (s *sqliteStore) insertBusinessDays(ctx context.Context, locationNumber string, dates []string, now time.Time) error {
	if len(dates) == 0 {
		return errors.New("no dates to insert")
	}
	valueRows := make([]string, 0, len(dates))
	for _, date := range dates {
		valueRows = append(valueRows, "("+sqliteStringLiteral(locationNumber)+", "+sqliteStringLiteral(date)+", 0, 0, "+strconv.FormatInt(now.Unix(), 10)+", "+strconv.FormatInt(now.Unix(), 10)+")")
	}
	statement := `
		BEGIN;
		INSERT INTO location_business_days (
			location_number, business_date, total_sales, labor_hours, created_at, updated_at
		) VALUES ` + strings.Join(valueRows, ", ") + `;
		COMMIT;
	`
	_, err := s.exec(ctx, statement, nil)
	return err
}

func (s *sqliteStore) listBusinessDays(ctx context.Context, locationNumber string) ([]businessDay, error) {
	rows, err := s.query(ctx, `
		SELECT id, location_number, business_date, total_sales, labor_hours, created_at, updated_at
		FROM location_business_days
		WHERE location_number = @location_number
		ORDER BY business_date DESC, id DESC;
	`, map[string]string{
		"location_number": locationNumber,
	})
	if err != nil {
		return nil, err
	}
	days := make([]businessDay, 0, len(rows))
	for _, row := range rows {
		id, err := valueAsInt64(row["id"])
		if err != nil {
			return nil, err
		}
		loc, err := valueAsString(row["location_number"])
		if err != nil {
			return nil, err
		}
		businessDate, err := valueAsString(row["business_date"])
		if err != nil {
			return nil, err
		}
		totalSales, err := valueAsFloat64(row["total_sales"])
		if err != nil {
			return nil, err
		}
		laborHours, err := valueAsFloat64(row["labor_hours"])
		if err != nil {
			return nil, err
		}
		createdAtUnix, err := valueAsInt64(row["created_at"])
		if err != nil {
			return nil, err
		}
		updatedAtUnix, err := valueAsInt64(row["updated_at"])
		if err != nil {
			return nil, err
		}
		days = append(days, businessDay{
			ID:           id,
			LocationNum:  loc,
			BusinessDate: businessDate,
			TotalSales:   totalSales,
			LaborHours:   laborHours,
			CreatedAt:    time.Unix(createdAtUnix, 0).UTC(),
			UpdatedAt:    time.Unix(updatedAtUnix, 0).UTC(),
		})
	}
	return days, nil
}

func (s *sqliteStore) updateBusinessDayMetrics(ctx context.Context, locationNumber string, dayID int64, totalSales, laborHours float64) error {
	rows, err := s.query(ctx, `
		SELECT COUNT(*) AS count
		FROM location_business_days
		WHERE id = @id AND location_number = @location_number;
	`, map[string]string{
		"id":              strconv.FormatInt(dayID, 10),
		"location_number": locationNumber,
	})
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		return errNotFound
	}
	count, err := valueAsInt64(rows[0]["count"])
	if err != nil {
		return err
	}
	if count == 0 {
		return errNotFound
	}
	_, err = s.exec(ctx, `
		UPDATE location_business_days
		SET total_sales = @total_sales,
			labor_hours = @labor_hours,
			updated_at = @updated_at
		WHERE id = @id
			AND location_number = @location_number;
	`, map[string]string{
		"id":              strconv.FormatInt(dayID, 10),
		"location_number": locationNumber,
		"total_sales":     strconv.FormatFloat(totalSales, 'f', -1, 64),
		"labor_hours":     strconv.FormatFloat(laborHours, 'f', -1, 64),
		"updated_at":      strconv.FormatInt(time.Now().UTC().Unix(), 10),
	})
	return err
}

func (s *sqliteStore) getBusinessDayByDate(ctx context.Context, locationNumber, businessDate string) (*businessDay, error) {
	rows, err := s.query(ctx, `
		SELECT id, location_number, business_date, total_sales, labor_hours, created_at, updated_at
		FROM location_business_days
		WHERE location_number = @location_number
			AND business_date = @business_date
		LIMIT 1;
	`, map[string]string{
		"location_number": locationNumber,
		"business_date":   businessDate,
	})
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, errNotFound
	}
	id, err := valueAsInt64(rows[0]["id"])
	if err != nil {
		return nil, err
	}
	totalSales, err := valueAsFloat64(rows[0]["total_sales"])
	if err != nil {
		return nil, err
	}
	laborHours, err := valueAsFloat64(rows[0]["labor_hours"])
	if err != nil {
		return nil, err
	}
	createdAtUnix, err := valueAsInt64(rows[0]["created_at"])
	if err != nil {
		return nil, err
	}
	updatedAtUnix, err := valueAsInt64(rows[0]["updated_at"])
	if err != nil {
		return nil, err
	}
	return &businessDay{
		ID:           id,
		LocationNum:  locationNumber,
		BusinessDate: businessDate,
		TotalSales:   totalSales,
		LaborHours:   laborHours,
		CreatedAt:    time.Unix(createdAtUnix, 0).UTC(),
		UpdatedAt:    time.Unix(updatedAtUnix, 0).UTC(),
	}, nil
}

func (s *sqliteStore) getOrCreateBusinessDay(ctx context.Context, locationNumber, businessDate string) (*businessDay, error) {
	day, err := s.getBusinessDayByDate(ctx, locationNumber, businessDate)
	if err == nil {
		return day, nil
	}
	if !errors.Is(err, errNotFound) {
		return nil, err
	}
	now := time.Now().UTC()
	if err := s.upsertBusinessDay(ctx, businessDay{
		LocationNum:  locationNumber,
		BusinessDate: businessDate,
		TotalSales:   0,
		LaborHours:   0,
		CreatedAt:    now,
		UpdatedAt:    now,
	}); err != nil {
		return nil, err
	}
	return s.getBusinessDayByDate(ctx, locationNumber, businessDate)
}

func (s *sqliteStore) updateBusinessDayMetricsByDate(ctx context.Context, locationNumber, businessDate string, totalSales, laborHours float64) error {
	rows, err := s.query(ctx, `
		SELECT COUNT(*) AS count
		FROM location_business_days
		WHERE location_number = @location_number
			AND business_date = @business_date;
	`, map[string]string{
		"location_number": locationNumber,
		"business_date":   businessDate,
	})
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		return errNotFound
	}
	count, err := valueAsInt64(rows[0]["count"])
	if err != nil {
		return err
	}
	if count == 0 {
		return errNotFound
	}
	_, err = s.exec(ctx, `
		UPDATE location_business_days
		SET total_sales = @total_sales,
			labor_hours = @labor_hours,
			updated_at = @updated_at
		WHERE location_number = @location_number
			AND business_date = @business_date;
	`, map[string]string{
		"location_number": locationNumber,
		"business_date":   businessDate,
		"total_sales":     strconv.FormatFloat(totalSales, 'f', -1, 64),
		"labor_hours":     strconv.FormatFloat(laborHours, 'f', -1, 64),
		"updated_at":      strconv.FormatInt(time.Now().UTC().Unix(), 10),
	})
	return err
}

func (s *sqliteStore) getLocationUniformToken(ctx context.Context, token string) (*locationUniformToken, error) {
	rows, err := s.query(ctx, `
		SELECT token, location_number
		FROM location_uniform_order_tokens
		WHERE token = @token
		LIMIT 1;
	`, map[string]string{"token": token})
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, errNotFound
	}
	locationNumber, err := valueAsString(rows[0]["location_number"])
	if err != nil {
		return nil, err
	}
	return &locationUniformToken{
		Token:          token,
		LocationNumber: locationNumber,
	}, nil
}

func (s *sqliteStore) getOrCreateLocationUniformToken(ctx context.Context, locationNumber string) (string, error) {
	rows, err := s.query(ctx, `
		SELECT token
		FROM location_uniform_order_tokens
		WHERE location_number = @location_number
		LIMIT 1;
	`, map[string]string{"location_number": locationNumber})
	if err != nil {
		return "", err
	}
	if len(rows) > 0 {
		token, err := valueAsString(rows[0]["token"])
		if err != nil {
			return "", err
		}
		if strings.TrimSpace(token) != "" {
			return token, nil
		}
	}
	token, err := randomToken(32)
	if err != nil {
		return "", err
	}
	_, err = s.exec(ctx, `
		INSERT INTO location_uniform_order_tokens (token, location_number, created_at)
		VALUES (@token, @location_number, @created_at)
		ON CONFLICT(location_number)
		DO UPDATE SET token = excluded.token;
	`, map[string]string{
		"token":           token,
		"location_number": locationNumber,
		"created_at":      strconv.FormatInt(time.Now().UTC().Unix(), 10),
	})
	if err != nil {
		return "", err
	}
	return token, nil
}

func (s *sqliteStore) getUniformItemBySystemKey(ctx context.Context, locationNumber, systemKey string) (*uniformItem, error) {
	rows, err := s.query(ctx, `
		SELECT id
		FROM location_uniform_items
		WHERE location_number = @location_number
			AND system_key = @system_key
		ORDER BY id DESC
		LIMIT 1;
	`, map[string]string{
		"location_number": locationNumber,
		"system_key":      strings.TrimSpace(systemKey),
	})
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, errNotFound
	}
	itemID, err := valueAsInt64(rows[0]["id"])
	if err != nil {
		return nil, err
	}
	return s.getUniformItemByID(ctx, locationNumber, itemID)
}

func appendUniformSizeFieldInsertStatements(parts *[]string, itemIDExpr, nowUnix string, sizeFields []uniformSizeField) {
	for fieldIdx, field := range sizeFields {
		for optionIdx, option := range field.Options {
			*parts = append(*parts, `INSERT INTO location_uniform_item_size_options (
				item_id, field_label, option_value, field_sort_order, option_sort_order, created_at
			) VALUES (
				`+itemIDExpr+`,
				`+sqliteStringLiteral(field.Label)+`,
				`+sqliteStringLiteral(option)+`,
				`+strconv.Itoa(fieldIdx)+`,
				`+strconv.Itoa(optionIdx)+`,
				`+nowUnix+`
			) ON CONFLICT(item_id, field_label, option_value) DO NOTHING;`)
		}
	}
	for idx, size := range flattenUniformSizeFields(sizeFields) {
		*parts = append(*parts, `INSERT INTO location_uniform_item_sizes (
			item_id, size_label, sort_order, created_at
		) VALUES (
			`+itemIDExpr+`,
			`+sqliteStringLiteral(size)+`,
			`+strconv.Itoa(idx)+`,
			`+nowUnix+`
		) ON CONFLICT(item_id, size_label) DO NOTHING;`)
	}
}

func (s *sqliteStore) createUniformItem(ctx context.Context, item uniformItem, priceCents int64, sizeFields []uniformSizeField) error {
	nowUnix := strconv.FormatInt(item.CreatedAt.UTC().Unix(), 10)
	parts := []string{
		"BEGIN;",
		`INSERT INTO location_uniform_items (
			location_number, name, price_cents, enabled, system_key, image_data, image_mime, created_at, updated_at
		) VALUES (
			` + sqliteStringLiteral(item.LocationNum) + `,
			` + sqliteStringLiteral(item.Name) + `,
			` + strconv.FormatInt(priceCents, 10) + `,
			1,
			` + sqliteStringLiteral(strings.TrimSpace(item.SystemKey)) + `,
			` + sqliteStringLiteral(item.ImageData) + `,
			` + sqliteStringLiteral(item.ImageMime) + `,
			` + nowUnix + `,
			` + nowUnix + `
		);`,
	}
	itemIDExpr := `(SELECT id FROM location_uniform_items WHERE location_number = ` + sqliteStringLiteral(item.LocationNum) + ` AND name = ` + sqliteStringLiteral(item.Name) + ` AND created_at = ` + nowUnix + ` ORDER BY id DESC LIMIT 1)`
	for idx, image := range item.Images {
		sortOrder := image.SortOrder
		if sortOrder < 0 {
			sortOrder = int64(idx)
		}
		parts = append(parts, `INSERT INTO location_uniform_item_images (
			item_id, image_data, image_mime, sort_order, created_at
		) VALUES (
			`+itemIDExpr+`,
			`+sqliteStringLiteral(image.ImageData)+`,
			`+sqliteStringLiteral(image.ImageMime)+`,
			`+strconv.FormatInt(sortOrder, 10)+`,
			`+nowUnix+`
		);`)
	}
	appendUniformSizeFieldInsertStatements(&parts, itemIDExpr, nowUnix, sizeFields)
	parts = append(parts, "COMMIT;")
	_, err := s.exec(ctx, strings.Join(parts, "\n"), nil)
	return err
}

func (s *sqliteStore) listUniformItems(ctx context.Context, locationNumber string, onlyEnabled bool) ([]uniformItem, error) {
	statement := `
		SELECT id, location_number, name, price_cents, enabled, system_key, image_data, image_mime, created_at, updated_at
		FROM location_uniform_items
		WHERE location_number = @location_number
	`
	if onlyEnabled {
		statement += " AND enabled = 1"
	}
	statement += " ORDER BY id DESC;"
	rows, err := s.query(ctx, statement, map[string]string{
		"location_number": locationNumber,
	})
	if err != nil {
		return nil, err
	}
	items := make([]uniformItem, 0, len(rows))
	for _, row := range rows {
		id, err := valueAsInt64(row["id"])
		if err != nil {
			return nil, err
		}
		locNum, err := valueAsString(row["location_number"])
		if err != nil {
			return nil, err
		}
		name, err := valueAsString(row["name"])
		if err != nil {
			return nil, err
		}
		priceCents, err := valueAsInt64(row["price_cents"])
		if err != nil {
			return nil, err
		}
		enabledRaw, err := valueAsInt64(row["enabled"])
		if err != nil {
			return nil, err
		}
		systemKey, err := valueAsString(row["system_key"])
		if err != nil {
			return nil, err
		}
		imageData, err := valueAsString(row["image_data"])
		if err != nil {
			return nil, err
		}
		imageMime, err := valueAsString(row["image_mime"])
		if err != nil {
			return nil, err
		}
		createdAtUnix, err := valueAsInt64(row["created_at"])
		if err != nil {
			return nil, err
		}
		updatedAtUnix, err := valueAsInt64(row["updated_at"])
		if err != nil {
			return nil, err
		}
		images, err := s.listUniformItemImages(ctx, id)
		if err != nil {
			return nil, err
		}
		sizeFields, err := s.listUniformItemSizeFields(ctx, id)
		if err != nil {
			return nil, err
		}
		if len(sizeFields) == 0 {
			legacySizes, err := s.listUniformItemSizes(ctx, id)
			if err != nil {
				return nil, err
			}
			sizeFields = legacyUniformSizeFields(legacySizes)
		}
		if len(images) > 0 {
			imageData = images[0].ImageData
			imageMime = images[0].ImageMime
		} else if strings.TrimSpace(imageData) != "" {
			images = append(images, uniformItemImage{
				ID:        0,
				ItemID:    id,
				ImageData: imageData,
				ImageMime: imageMime,
				SortOrder: 0,
			})
		}
		items = append(items, uniformItem{
			ID:          id,
			LocationNum: locNum,
			Name:        name,
			Price:       float64(priceCents) / 100.0,
			Enabled:     enabledRaw == 1,
			SystemKey:   strings.TrimSpace(systemKey),
			ImageData:   imageData,
			ImageMime:   imageMime,
			Images:      images,
			Sizes:       flattenUniformSizeFields(sizeFields),
			SizeFields:  sizeFields,
			CreatedAt:   time.Unix(createdAtUnix, 0).UTC(),
			UpdatedAt:   time.Unix(updatedAtUnix, 0).UTC(),
		})
	}
	return items, nil
}

func (s *sqliteStore) getUniformItemByID(ctx context.Context, locationNumber string, itemID int64) (*uniformItem, error) {
	rows, err := s.query(ctx, `
		SELECT id, location_number, name, price_cents, enabled, system_key, image_data, image_mime, created_at, updated_at
		FROM location_uniform_items
		WHERE id = @id AND location_number = @location_number
		LIMIT 1;
	`, map[string]string{
		"id":              strconv.FormatInt(itemID, 10),
		"location_number": locationNumber,
	})
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, errNotFound
	}
	id, err := valueAsInt64(rows[0]["id"])
	if err != nil {
		return nil, err
	}
	locNum, err := valueAsString(rows[0]["location_number"])
	if err != nil {
		return nil, err
	}
	name, err := valueAsString(rows[0]["name"])
	if err != nil {
		return nil, err
	}
	priceCents, err := valueAsInt64(rows[0]["price_cents"])
	if err != nil {
		return nil, err
	}
	enabledRaw, err := valueAsInt64(rows[0]["enabled"])
	if err != nil {
		return nil, err
	}
	systemKey, err := valueAsString(rows[0]["system_key"])
	if err != nil {
		return nil, err
	}
	imageData, err := valueAsString(rows[0]["image_data"])
	if err != nil {
		return nil, err
	}
	imageMime, err := valueAsString(rows[0]["image_mime"])
	if err != nil {
		return nil, err
	}
	createdAtUnix, err := valueAsInt64(rows[0]["created_at"])
	if err != nil {
		return nil, err
	}
	updatedAtUnix, err := valueAsInt64(rows[0]["updated_at"])
	if err != nil {
		return nil, err
	}
	images, err := s.listUniformItemImages(ctx, id)
	if err != nil {
		return nil, err
	}
	sizeFields, err := s.listUniformItemSizeFields(ctx, id)
	if err != nil {
		return nil, err
	}
	if len(sizeFields) == 0 {
		legacySizes, err := s.listUniformItemSizes(ctx, id)
		if err != nil {
			return nil, err
		}
		sizeFields = legacyUniformSizeFields(legacySizes)
	}
	if len(images) > 0 {
		imageData = images[0].ImageData
		imageMime = images[0].ImageMime
	} else if strings.TrimSpace(imageData) != "" {
		images = append(images, uniformItemImage{
			ID:        0,
			ItemID:    id,
			ImageData: imageData,
			ImageMime: imageMime,
			SortOrder: 0,
		})
	}
	return &uniformItem{
		ID:          id,
		LocationNum: locNum,
		Name:        name,
		Price:       float64(priceCents) / 100.0,
		Enabled:     enabledRaw == 1,
		SystemKey:   strings.TrimSpace(systemKey),
		ImageData:   imageData,
		ImageMime:   imageMime,
		Images:      images,
		Sizes:       flattenUniformSizeFields(sizeFields),
		SizeFields:  sizeFields,
		CreatedAt:   time.Unix(createdAtUnix, 0).UTC(),
		UpdatedAt:   time.Unix(updatedAtUnix, 0).UTC(),
	}, nil
}

func (s *sqliteStore) listUniformItemImages(ctx context.Context, itemID int64) ([]uniformItemImage, error) {
	rows, err := s.query(ctx, `
		SELECT id, item_id, image_data, image_mime, sort_order
		FROM location_uniform_item_images
		WHERE item_id = @item_id
		ORDER BY sort_order ASC, id ASC;
	`, map[string]string{
		"item_id": strconv.FormatInt(itemID, 10),
	})
	if err != nil {
		return nil, err
	}
	images := make([]uniformItemImage, 0, len(rows))
	for _, row := range rows {
		id, err := valueAsInt64(row["id"])
		if err != nil {
			return nil, err
		}
		itemIDValue, err := valueAsInt64(row["item_id"])
		if err != nil {
			return nil, err
		}
		imageData, err := valueAsString(row["image_data"])
		if err != nil {
			return nil, err
		}
		imageMime, err := valueAsString(row["image_mime"])
		if err != nil {
			return nil, err
		}
		sortOrder, err := valueAsInt64(row["sort_order"])
		if err != nil {
			return nil, err
		}
		images = append(images, uniformItemImage{
			ID:        id,
			ItemID:    itemIDValue,
			ImageData: imageData,
			ImageMime: imageMime,
			SortOrder: sortOrder,
		})
	}
	return images, nil
}

func (s *sqliteStore) listUniformItemSizes(ctx context.Context, itemID int64) ([]string, error) {
	rows, err := s.query(ctx, `
		SELECT size_label
		FROM location_uniform_item_sizes
		WHERE item_id = @item_id
		ORDER BY sort_order ASC, id ASC;
	`, map[string]string{
		"item_id": strconv.FormatInt(itemID, 10),
	})
	if err != nil {
		return nil, err
	}
	sizes := make([]string, 0, len(rows))
	for _, row := range rows {
		size, err := valueAsString(row["size_label"])
		if err != nil {
			return nil, err
		}
		size = strings.TrimSpace(size)
		if size == "" {
			continue
		}
		sizes = append(sizes, size)
	}
	return sizes, nil
}

func (s *sqliteStore) listUniformItemSizeFields(ctx context.Context, itemID int64) ([]uniformSizeField, error) {
	rows, err := s.query(ctx, `
		SELECT field_label, option_value
		FROM location_uniform_item_size_options
		WHERE item_id = @item_id
		ORDER BY field_sort_order ASC, option_sort_order ASC, id ASC;
	`, map[string]string{
		"item_id": strconv.FormatInt(itemID, 10),
	})
	if err != nil {
		return nil, err
	}
	fields := make([]uniformSizeField, 0)
	fieldIdxByKey := map[string]int{}
	for _, row := range rows {
		label, err := valueAsString(row["field_label"])
		if err != nil {
			return nil, err
		}
		option, err := valueAsString(row["option_value"])
		if err != nil {
			return nil, err
		}
		label = strings.TrimSpace(label)
		option = strings.TrimSpace(option)
		if label == "" || option == "" {
			continue
		}
		key := strings.ToLower(label)
		idx, ok := fieldIdxByKey[key]
		if !ok {
			fieldIdxByKey[key] = len(fields)
			fields = append(fields, uniformSizeField{Label: label, Options: []string{}})
			idx = len(fields) - 1
		}
		if containsIgnoreCase(fields[idx].Options, option) {
			continue
		}
		fields[idx].Options = append(fields[idx].Options, option)
	}
	return fields, nil
}

func (s *sqliteStore) moveUniformItemImage(ctx context.Context, locationNumber string, itemID, imageID int64, direction string) error {
	itemRows, err := s.query(ctx, `
		SELECT COUNT(*) AS count
		FROM location_uniform_items
		WHERE id = @id AND location_number = @location_number;
	`, map[string]string{
		"id":              strconv.FormatInt(itemID, 10),
		"location_number": locationNumber,
	})
	if err != nil {
		return err
	}
	if len(itemRows) == 0 {
		return errNotFound
	}
	itemCount, err := valueAsInt64(itemRows[0]["count"])
	if err != nil {
		return err
	}
	if itemCount == 0 {
		return errNotFound
	}

	images, err := s.listUniformItemImages(ctx, itemID)
	if err != nil {
		return err
	}
	if len(images) == 0 {
		return errNotFound
	}
	currentIdx := -1
	for idx, img := range images {
		if img.ID == imageID {
			currentIdx = idx
			break
		}
	}
	if currentIdx < 0 {
		return errNotFound
	}
	targetIdx := currentIdx
	if direction == "up" && currentIdx > 0 {
		targetIdx = currentIdx - 1
	}
	if direction == "down" && currentIdx < len(images)-1 {
		targetIdx = currentIdx + 1
	}
	if targetIdx == currentIdx {
		return nil
	}
	images[currentIdx], images[targetIdx] = images[targetIdx], images[currentIdx]

	parts := []string{"BEGIN;"}
	for idx, img := range images {
		parts = append(parts, `
			UPDATE location_uniform_item_images
			SET sort_order = `+strconv.Itoa(idx)+`
			WHERE id = `+strconv.FormatInt(img.ID, 10)+`;
		`)
	}
	parts = append(parts, "COMMIT;")
	_, err = s.exec(ctx, strings.Join(parts, "\n"), nil)
	return err
}

func (s *sqliteStore) appendUniformItemImages(ctx context.Context, locationNumber string, itemID int64, images []uniformItemImage) error {
	if len(images) == 0 {
		return errors.New("no images to append")
	}
	if _, err := s.getUniformItemByID(ctx, locationNumber, itemID); err != nil {
		return err
	}
	rows, err := s.query(ctx, `
		SELECT COALESCE(MAX(sort_order), -1) AS max_sort
		FROM location_uniform_item_images
		WHERE item_id = @item_id;
	`, map[string]string{
		"item_id": strconv.FormatInt(itemID, 10),
	})
	if err != nil {
		return err
	}
	maxSort := int64(-1)
	if len(rows) > 0 {
		maxSort, err = valueAsInt64(rows[0]["max_sort"])
		if err != nil {
			return err
		}
	}
	nowUnix := strconv.FormatInt(time.Now().UTC().Unix(), 10)
	for idx, image := range images {
		if _, err := s.exec(ctx, `
			INSERT INTO location_uniform_item_images (item_id, image_data, image_mime, sort_order, created_at)
			VALUES (@item_id, @image_data, @image_mime, @sort_order, @created_at);
		`, map[string]string{
			"item_id":    strconv.FormatInt(itemID, 10),
			"image_data": image.ImageData,
			"image_mime": image.ImageMime,
			"sort_order": strconv.FormatInt(maxSort+1+int64(idx), 10),
			"created_at": nowUnix,
		}); err != nil {
			return err
		}
	}
	return nil
}

func (s *sqliteStore) deleteUniformItemImage(ctx context.Context, locationNumber string, itemID, imageID int64) error {
	if _, err := s.getUniformItemByID(ctx, locationNumber, itemID); err != nil {
		return err
	}
	rows, err := s.query(ctx, `
		SELECT COUNT(*) AS count
		FROM location_uniform_item_images
		WHERE id = @image_id AND item_id = @item_id;
	`, map[string]string{
		"image_id": strconv.FormatInt(imageID, 10),
		"item_id":  strconv.FormatInt(itemID, 10),
	})
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		return errNotFound
	}
	count, err := valueAsInt64(rows[0]["count"])
	if err != nil {
		return err
	}
	if count == 0 {
		return errNotFound
	}
	if _, err := s.exec(ctx, `
		DELETE FROM location_uniform_item_images
		WHERE id = @image_id AND item_id = @item_id;
	`, map[string]string{
		"image_id": strconv.FormatInt(imageID, 10),
		"item_id":  strconv.FormatInt(itemID, 10),
	}); err != nil {
		return err
	}
	images, err := s.listUniformItemImages(ctx, itemID)
	if err != nil {
		return err
	}
	parts := []string{"BEGIN;"}
	for idx, img := range images {
		parts = append(parts, `
			UPDATE location_uniform_item_images
			SET sort_order = `+strconv.Itoa(idx)+`
			WHERE id = `+strconv.FormatInt(img.ID, 10)+`;
		`)
	}
	parts = append(parts, "COMMIT;")
	_, err = s.exec(ctx, strings.Join(parts, "\n"), nil)
	return err
}

func (s *sqliteStore) updateUniformItem(ctx context.Context, locationNumber string, itemID int64, name string, priceCents int64, sizeFields []uniformSizeField) error {
	rows, err := s.query(ctx, `
		SELECT COUNT(*) AS count
		FROM location_uniform_items
		WHERE id = @id AND location_number = @location_number;
	`, map[string]string{
		"id":              strconv.FormatInt(itemID, 10),
		"location_number": locationNumber,
	})
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		return errNotFound
	}
	count, err := valueAsInt64(rows[0]["count"])
	if err != nil {
		return err
	}
	if count == 0 {
		return errNotFound
	}
	_, err = s.exec(ctx, `
		UPDATE location_uniform_items
		SET name = @name,
			price_cents = @price_cents,
			updated_at = @updated_at
		WHERE id = @id
			AND location_number = @location_number;
	`, map[string]string{
		"id":              strconv.FormatInt(itemID, 10),
		"location_number": locationNumber,
		"name":            name,
		"price_cents":     strconv.FormatInt(priceCents, 10),
		"updated_at":      strconv.FormatInt(time.Now().UTC().Unix(), 10),
	})
	if err != nil {
		return err
	}
	if _, err := s.exec(ctx, `
		DELETE FROM location_uniform_item_sizes
		WHERE item_id = @item_id;
	`, map[string]string{
		"item_id": strconv.FormatInt(itemID, 10),
	}); err != nil {
		return err
	}
	if _, err := s.exec(ctx, `
		DELETE FROM location_uniform_item_size_options
		WHERE item_id = @item_id;
	`, map[string]string{
		"item_id": strconv.FormatInt(itemID, 10),
	}); err != nil {
		return err
	}
	nowUnix := strconv.FormatInt(time.Now().UTC().Unix(), 10)
	for fieldIdx, field := range sizeFields {
		for optionIdx, option := range field.Options {
			if _, err := s.exec(ctx, `
				INSERT INTO location_uniform_item_size_options (item_id, field_label, option_value, field_sort_order, option_sort_order, created_at)
				VALUES (@item_id, @field_label, @option_value, @field_sort_order, @option_sort_order, @created_at);
			`, map[string]string{
				"item_id":           strconv.FormatInt(itemID, 10),
				"field_label":       field.Label,
				"option_value":      option,
				"field_sort_order":  strconv.Itoa(fieldIdx),
				"option_sort_order": strconv.Itoa(optionIdx),
				"created_at":        nowUnix,
			}); err != nil {
				return err
			}
		}
	}
	for idx, size := range flattenUniformSizeFields(sizeFields) {
		if _, err := s.exec(ctx, `
			INSERT INTO location_uniform_item_sizes (item_id, size_label, sort_order, created_at)
			VALUES (@item_id, @size_label, @sort_order, @created_at);
		`, map[string]string{
			"item_id":    strconv.FormatInt(itemID, 10),
			"size_label": size,
			"sort_order": strconv.Itoa(idx),
			"created_at": nowUnix,
		}); err != nil {
			return err
		}
	}
	return nil
}

func (s *sqliteStore) deleteUniformItem(ctx context.Context, locationNumber string, itemID int64) error {
	rows, err := s.query(ctx, `
		SELECT COUNT(*) AS count
		FROM location_uniform_items
		WHERE id = @id AND location_number = @location_number;
	`, map[string]string{
		"id":              strconv.FormatInt(itemID, 10),
		"location_number": locationNumber,
	})
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		return errNotFound
	}
	count, err := valueAsInt64(rows[0]["count"])
	if err != nil {
		return err
	}
	if count == 0 {
		return errNotFound
	}
	_, err = s.exec(ctx, `
		DELETE FROM location_uniform_items
		WHERE id = @id
			AND location_number = @location_number;
	`, map[string]string{
		"id":              strconv.FormatInt(itemID, 10),
		"location_number": locationNumber,
	})
	return err
}

func (s *sqliteStore) createUniformOrder(ctx context.Context, locationNumber, timePunchName string, lines []uniformOrderLineInput) error {
	if len(lines) == 0 {
		return errors.New("no order lines")
	}
	now := time.Now().UTC().Unix()
	totalCents := int64(0)
	lineValues := make([]string, 0, len(lines))
	for _, line := range lines {
		lineTotal := line.UnitPriceCents * line.Quantity
		totalCents += lineTotal
		lineValues = append(lineValues, "((SELECT last_insert_rowid()), "+
			strconv.FormatInt(line.ItemID, 10)+", "+
			sqliteStringLiteral(line.ItemName)+", "+
			sqliteStringLiteral(line.ItemNumber)+", "+
			sqliteStringLiteral(line.Size)+", "+
			sqliteStringLiteral(line.ExternalURL)+", "+
			sqliteStringLiteral(line.Note)+", "+
			strconv.FormatInt(line.Quantity, 10)+", "+
			strconv.FormatInt(line.UnitPriceCents, 10)+", "+
			strconv.FormatInt(lineTotal, 10)+", "+
			strconv.FormatInt(now, 10)+")")
	}
	statement := `
		BEGIN;
		INSERT INTO location_uniform_orders (location_number, time_punch_name, total_cents, created_at)
		VALUES (` + sqliteStringLiteral(locationNumber) + `, ` + sqliteStringLiteral(timePunchName) + `, ` + strconv.FormatInt(totalCents, 10) + `, ` + strconv.FormatInt(now, 10) + `);
		INSERT INTO location_uniform_order_lines (
			order_id, item_id, item_name, item_number, size_option, external_url, note, quantity, unit_price_cents, line_total_cents, created_at
		) VALUES ` + strings.Join(lineValues, ", ") + `;
		COMMIT;
	`
	_, err := s.exec(ctx, statement, nil)
	return err
}

func (s *sqliteStore) listUniformOrders(ctx context.Context, locationNumber string, archived bool) ([]uniformOrder, error) {
	archivedFilter := "o.archived_at = 0"
	if archived {
		archivedFilter = "o.archived_at > 0"
	}
	rows, err := s.query(ctx, `
		SELECT
			o.id,
			o.location_number,
			o.time_punch_name,
			o.total_cents,
			o.archived_at,
			o.created_at,
			COALESCE((
				SELECT GROUP_CONCAT(
					l.item_name ||
					CASE WHEN TRIM(COALESCE(l.size_option, '')) <> '' THEN ' (' || l.size_option || ')' ELSE '' END ||
					' x' || l.quantity ||
					CASE WHEN TRIM(COALESCE(l.note, '')) <> '' THEN ' (note: ' || l.note || ')' ELSE '' END,
					', '
				)
				FROM location_uniform_order_lines l
				WHERE l.order_id = o.id
			), '') AS items_summary
		FROM location_uniform_orders o
		WHERE o.location_number = @location_number
			AND `+archivedFilter+`
		ORDER BY o.created_at DESC, o.id DESC;
	`, map[string]string{
		"location_number": locationNumber,
	})
	if err != nil {
		return nil, err
	}
	orders := make([]uniformOrder, 0, len(rows))
	for _, row := range rows {
		id, err := valueAsInt64(row["id"])
		if err != nil {
			return nil, err
		}
		locNum, err := valueAsString(row["location_number"])
		if err != nil {
			return nil, err
		}
		timePunchName, err := valueAsString(row["time_punch_name"])
		if err != nil {
			return nil, err
		}
		totalCents, err := valueAsInt64(row["total_cents"])
		if err != nil {
			return nil, err
		}
		archivedAtUnix, err := valueAsInt64(row["archived_at"])
		if err != nil {
			return nil, err
		}
		createdAtUnix, err := valueAsInt64(row["created_at"])
		if err != nil {
			return nil, err
		}
		itemsSummary, err := valueAsString(row["items_summary"])
		if err != nil {
			return nil, err
		}
		archivedAt := time.Time{}
		if archivedAtUnix > 0 {
			archivedAt = time.Unix(archivedAtUnix, 0).UTC()
		}
		orders = append(orders, uniformOrder{
			ID:            id,
			LocationNum:   locNum,
			TimePunchName: timePunchName,
			ItemsSummary:  itemsSummary,
			Lines:         []uniformOrderLine{},
			Total:         float64(totalCents) / 100.0,
			CreatedAt:     time.Unix(createdAtUnix, 0).UTC(),
			ArchivedAt:    archivedAt,
		})
	}

	for i := range orders {
		lines, err := s.listUniformOrderLines(ctx, orders[i].ID)
		if err != nil {
			return nil, err
		}
		orders[i].Lines = lines
	}
	return orders, nil
}

func (s *sqliteStore) listUniformOrderLines(ctx context.Context, orderID int64) ([]uniformOrderLine, error) {
	rows, err := s.query(ctx, `
		SELECT
			id,
			order_id,
			item_id,
			item_name,
			item_number,
			size_option,
			external_url,
			note,
			quantity,
			unit_price_cents,
			line_total_cents,
			purchased_at,
			charged_back_cents
		FROM location_uniform_order_lines
		WHERE order_id = @order_id
		ORDER BY id ASC;
	`, map[string]string{
		"order_id": strconv.FormatInt(orderID, 10),
	})
	if err != nil {
		return nil, err
	}
	lines := make([]uniformOrderLine, 0, len(rows))
	for _, row := range rows {
		id, err := valueAsInt64(row["id"])
		if err != nil {
			return nil, err
		}
		orderIDValue, err := valueAsInt64(row["order_id"])
		if err != nil {
			return nil, err
		}
		itemID, err := valueAsInt64(row["item_id"])
		if err != nil {
			return nil, err
		}
		itemName, err := valueAsString(row["item_name"])
		if err != nil {
			return nil, err
		}
		itemNumber, err := valueAsString(row["item_number"])
		if err != nil {
			return nil, err
		}
		sizeOption, err := valueAsString(row["size_option"])
		if err != nil {
			return nil, err
		}
		externalURL, err := valueAsString(row["external_url"])
		if err != nil {
			return nil, err
		}
		note, err := valueAsString(row["note"])
		if err != nil {
			return nil, err
		}
		quantity, err := valueAsInt64(row["quantity"])
		if err != nil {
			return nil, err
		}
		unitPriceCents, err := valueAsInt64(row["unit_price_cents"])
		if err != nil {
			return nil, err
		}
		lineTotalCents, err := valueAsInt64(row["line_total_cents"])
		if err != nil {
			return nil, err
		}
		purchasedAtUnix, err := valueAsInt64(row["purchased_at"])
		if err != nil {
			return nil, err
		}
		chargedBackCents, err := valueAsInt64(row["charged_back_cents"])
		if err != nil {
			return nil, err
		}
		remainingCents := lineTotalCents - chargedBackCents
		if remainingCents < 0 {
			remainingCents = 0
		}
		purchasedAt := time.Time{}
		purchased := purchasedAtUnix > 0
		if purchased {
			purchasedAt = time.Unix(purchasedAtUnix, 0).UTC()
		}
		lines = append(lines, uniformOrderLine{
			ID:          id,
			OrderID:     orderIDValue,
			ItemID:      itemID,
			ItemName:    itemName,
			ItemNumber:  itemNumber,
			SizeOption:  sizeOption,
			ExternalURL: strings.TrimSpace(externalURL),
			Note:        note,
			Quantity:    quantity,
			UnitPrice:   float64(unitPriceCents) / 100.0,
			LineTotal:   float64(lineTotalCents) / 100.0,
			Purchased:   purchased,
			PurchasedAt: purchasedAt,
			ChargedBack: float64(chargedBackCents) / 100.0,
			Remaining:   float64(remainingCents) / 100.0,
		})
	}
	return lines, nil
}

func (s *sqliteStore) archiveUniformOrder(ctx context.Context, locationNumber string, orderID int64) error {
	rows, err := s.query(ctx, `
		SELECT COUNT(*) AS count
		FROM location_uniform_orders
		WHERE id = @id
			AND location_number = @location_number
			AND archived_at = 0;
	`, map[string]string{
		"id":              strconv.FormatInt(orderID, 10),
		"location_number": locationNumber,
	})
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		return errNotFound
	}
	count, err := valueAsInt64(rows[0]["count"])
	if err != nil {
		return err
	}
	if count == 0 {
		return errNotFound
	}
	_, err = s.exec(ctx, `
		UPDATE location_uniform_orders
		SET archived_at = @archived_at
		WHERE id = @id
			AND location_number = @location_number
			AND archived_at = 0;
	`, map[string]string{
		"id":              strconv.FormatInt(orderID, 10),
		"location_number": locationNumber,
		"archived_at":     strconv.FormatInt(time.Now().UTC().Unix(), 10),
	})
	if err != nil {
		return err
	}
	return nil
}

func (s *sqliteStore) updateUniformOrderLineSettlement(ctx context.Context, locationNumber string, orderID, lineID int64, purchased bool, chargedBackCents int64) (bool, error) {
	rows, err := s.query(ctx, `
		SELECT
			l.line_total_cents,
			o.archived_at
		FROM location_uniform_order_lines l
		INNER JOIN location_uniform_orders o ON o.id = l.order_id
		WHERE l.id = @line_id
			AND l.order_id = @order_id
			AND o.location_number = @location_number
		LIMIT 1;
	`, map[string]string{
		"line_id":         strconv.FormatInt(lineID, 10),
		"order_id":        strconv.FormatInt(orderID, 10),
		"location_number": locationNumber,
	})
	if err != nil {
		return false, err
	}
	if len(rows) == 0 {
		return false, errNotFound
	}
	lineTotalCents, err := valueAsInt64(rows[0]["line_total_cents"])
	if err != nil {
		return false, err
	}
	archivedAt, err := valueAsInt64(rows[0]["archived_at"])
	if err != nil {
		return false, err
	}
	if archivedAt > 0 {
		return false, errors.New("uniform order is already archived")
	}
	if chargedBackCents < 0 {
		return false, errors.New("charged back amount cannot be negative")
	}
	if chargedBackCents > lineTotalCents {
		return false, errors.New("charged back amount cannot exceed line total")
	}
	if !purchased && chargedBackCents > 0 {
		return false, errors.New("line must be marked purchased before charging back")
	}

	purchasedAt := int64(0)
	if purchased {
		purchasedAt = time.Now().UTC().Unix()
	}

	_, err = s.exec(ctx, `
		UPDATE location_uniform_order_lines
		SET purchased_at = @purchased_at,
			charged_back_cents = @charged_back_cents
		WHERE id = @line_id
			AND order_id = @order_id;
	`, map[string]string{
		"purchased_at":       strconv.FormatInt(purchasedAt, 10),
		"charged_back_cents": strconv.FormatInt(chargedBackCents, 10),
		"line_id":            strconv.FormatInt(lineID, 10),
		"order_id":           strconv.FormatInt(orderID, 10),
	})
	if err != nil {
		return false, err
	}

	stateRows, err := s.query(ctx, `
		SELECT
			COUNT(*) AS total_lines,
			SUM(
				CASE
					WHEN purchased_at > 0 AND charged_back_cents >= line_total_cents THEN 1
					ELSE 0
				END
			) AS settled_lines
		FROM location_uniform_order_lines
		WHERE order_id = @order_id;
	`, map[string]string{
		"order_id": strconv.FormatInt(orderID, 10),
	})
	if err != nil {
		return false, err
	}
	if len(stateRows) == 0 {
		return false, nil
	}
	totalLines, err := valueAsInt64(stateRows[0]["total_lines"])
	if err != nil {
		return false, err
	}
	settledLines, err := valueAsInt64(stateRows[0]["settled_lines"])
	if err != nil {
		return false, err
	}
	if totalLines > 0 && settledLines == totalLines {
		_, err = s.exec(ctx, `
			UPDATE location_uniform_orders
			SET archived_at = @archived_at
			WHERE id = @order_id
				AND location_number = @location_number
				AND archived_at = 0;
		`, map[string]string{
			"archived_at":     strconv.FormatInt(time.Now().UTC().Unix(), 10),
			"order_id":        strconv.FormatInt(orderID, 10),
			"location_number": locationNumber,
		})
		if err != nil {
			return false, err
		}
		return true, nil
	}
	return false, nil
}

func (s *sqliteStore) deleteArchivedUniformOrder(ctx context.Context, locationNumber string, orderID int64) error {
	rows, err := s.query(ctx, `
		SELECT COUNT(*) AS count
		FROM location_uniform_orders
		WHERE id = @id
			AND location_number = @location_number
			AND archived_at > 0;
	`, map[string]string{
		"id":              strconv.FormatInt(orderID, 10),
		"location_number": locationNumber,
	})
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		return errNotFound
	}
	count, err := valueAsInt64(rows[0]["count"])
	if err != nil {
		return err
	}
	if count == 0 {
		return errNotFound
	}
	_, err = s.exec(ctx, `
		DELETE FROM location_uniform_orders
		WHERE id = @id
			AND location_number = @location_number
			AND archived_at > 0;
	`, map[string]string{
		"id":              strconv.FormatInt(orderID, 10),
		"location_number": locationNumber,
	})
	if err != nil {
		return err
	}
	return nil
}

func (s *sqliteStore) lookupUserByUsername(ctx context.Context, username string) (*userRecord, string, error) {
	rows, err := s.query(ctx, `
		SELECT id, username, password_hash, is_admin, role, access_level, location_number, time_punch_name
		FROM users
		WHERE username = @username
		LIMIT 1;
	`, map[string]string{"username": username})
	if err != nil {
		return nil, "", err
	}
	if len(rows) == 0 {
		return nil, "", errNotFound
	}

	id, err := valueAsInt64(rows[0]["id"])
	if err != nil {
		return nil, "", err
	}
	name, err := valueAsString(rows[0]["username"])
	if err != nil {
		return nil, "", err
	}
	hash, err := valueAsString(rows[0]["password_hash"])
	if err != nil {
		return nil, "", err
	}
	isAdminRaw, err := valueAsInt64(rows[0]["is_admin"])
	if err != nil {
		return nil, "", err
	}
	role, err := valueAsString(rows[0]["role"])
	if err != nil {
		return nil, "", err
	}
	accessLevel, err := valueAsString(rows[0]["access_level"])
	if err != nil {
		return nil, "", err
	}
	locationNumber, err := valueAsString(rows[0]["location_number"])
	if err != nil {
		return nil, "", err
	}
	timePunchName, err := valueAsString(rows[0]["time_punch_name"])
	if err != nil {
		return nil, "", err
	}

	return &userRecord{
		ID:             id,
		Username:       name,
		IsAdmin:        isAdminRaw == 1,
		Role:           strings.TrimSpace(role),
		AccessLevel:    strings.TrimSpace(accessLevel),
		LocationNumber: strings.TrimSpace(locationNumber),
		TimePunchName:  strings.TrimSpace(timePunchName),
	}, hash, nil
}

func (s *sqliteStore) lookupTeamUserByLocationAndTimePunch(ctx context.Context, locationNumber, timePunchName string) (*userRecord, string, error) {
	rows, err := s.query(ctx, `
		SELECT id, username, password_hash, is_admin, role, access_level, location_number, time_punch_name
		FROM users
		WHERE role = @role
			AND location_number = @location_number
			AND time_punch_name = @time_punch_name
		LIMIT 1;
	`, map[string]string{
		"role":            userRoleTeam,
		"location_number": locationNumber,
		"time_punch_name": timePunchName,
	})
	if err != nil {
		return nil, "", err
	}
	if len(rows) == 0 {
		return nil, "", errNotFound
	}
	id, err := valueAsInt64(rows[0]["id"])
	if err != nil {
		return nil, "", err
	}
	username, err := valueAsString(rows[0]["username"])
	if err != nil {
		return nil, "", err
	}
	hash, err := valueAsString(rows[0]["password_hash"])
	if err != nil {
		return nil, "", err
	}
	accessLevel, err := valueAsString(rows[0]["access_level"])
	if err != nil {
		return nil, "", err
	}
	return &userRecord{
		ID:             id,
		Username:       strings.TrimSpace(username),
		IsAdmin:        false,
		Role:           userRoleTeam,
		AccessLevel:    strings.TrimSpace(accessLevel),
		LocationNumber: strings.TrimSpace(locationNumber),
		TimePunchName:  strings.TrimSpace(timePunchName),
	}, hash, nil
}

func (s *sqliteStore) lookupRestaurantUserByLocation(ctx context.Context, locationNumber string) (*userRecord, string, error) {
	rows, err := s.query(ctx, `
		SELECT id, username, password_hash, is_admin, role, access_level, location_number, time_punch_name
		FROM users
		WHERE role = @role
			AND location_number = @location_number
		LIMIT 1;
	`, map[string]string{
		"role":            userRoleRestaurant,
		"location_number": strings.TrimSpace(locationNumber),
	})
	if err != nil {
		return nil, "", err
	}
	if len(rows) == 0 {
		return nil, "", errNotFound
	}
	id, err := valueAsInt64(rows[0]["id"])
	if err != nil {
		return nil, "", err
	}
	username, err := valueAsString(rows[0]["username"])
	if err != nil {
		return nil, "", err
	}
	hash, err := valueAsString(rows[0]["password_hash"])
	if err != nil {
		return nil, "", err
	}
	accessLevel, err := valueAsString(rows[0]["access_level"])
	if err != nil {
		return nil, "", err
	}
	locationNum, err := valueAsString(rows[0]["location_number"])
	if err != nil {
		return nil, "", err
	}
	timePunchName, err := valueAsString(rows[0]["time_punch_name"])
	if err != nil {
		return nil, "", err
	}
	return &userRecord{
		ID:             id,
		Username:       strings.TrimSpace(username),
		IsAdmin:        false,
		Role:           userRoleRestaurant,
		AccessLevel:    strings.TrimSpace(accessLevel),
		LocationNumber: strings.TrimSpace(locationNum),
		TimePunchName:  strings.TrimSpace(timePunchName),
	}, hash, nil
}

func (s *sqliteStore) lookupTeamUserByLocationAndPIN(ctx context.Context, locationNumber, pin string) (*userRecord, error) {
	rows, err := s.query(ctx, `
		SELECT id, username, password_hash, access_level, location_number, time_punch_name
		FROM users
		WHERE role = @role
			AND location_number = @location_number;
	`, map[string]string{
		"role":            userRoleTeam,
		"location_number": strings.TrimSpace(locationNumber),
	})
	if err != nil {
		return nil, err
	}
	pin = strings.TrimSpace(pin)
	var matched *userRecord
	for _, row := range rows {
		hash, err := valueAsString(row["password_hash"])
		if err != nil {
			return nil, err
		}
		if !security.VerifyPassword(pin, hash) {
			continue
		}
		id, err := valueAsInt64(row["id"])
		if err != nil {
			return nil, err
		}
		username, err := valueAsString(row["username"])
		if err != nil {
			return nil, err
		}
		locationNum, err := valueAsString(row["location_number"])
		if err != nil {
			return nil, err
		}
		accessLevel, err := valueAsString(row["access_level"])
		if err != nil {
			return nil, err
		}
		timePunchName, err := valueAsString(row["time_punch_name"])
		if err != nil {
			return nil, err
		}
		if matched != nil {
			return nil, errNotFound
		}
		matched = &userRecord{
			ID:             id,
			Username:       strings.TrimSpace(username),
			IsAdmin:        false,
			Role:           userRoleTeam,
			AccessLevel:    strings.TrimSpace(accessLevel),
			LocationNumber: strings.TrimSpace(locationNum),
			TimePunchName:  strings.TrimSpace(timePunchName),
		}
	}
	if matched == nil {
		return nil, errNotFound
	}
	return matched, nil
}

func (s *sqliteStore) upsertTeamMemberPIN(ctx context.Context, locationNumber, timePunchName, pin string) error {
	existingRows, err := s.query(ctx, `
		SELECT password_hash, time_punch_name
		FROM users
		WHERE role = @role
			AND location_number = @location_number;
	`, map[string]string{
		"role":            userRoleTeam,
		"location_number": strings.TrimSpace(locationNumber),
	})
	if err != nil {
		return err
	}
	for _, row := range existingRows {
		hash, err := valueAsString(row["password_hash"])
		if err != nil {
			return err
		}
		if !security.VerifyPassword(pin, hash) {
			continue
		}
		existingTimePunchName, err := valueAsString(row["time_punch_name"])
		if err != nil {
			return err
		}
		if strings.TrimSpace(existingTimePunchName) != strings.TrimSpace(timePunchName) {
			return errPINInUse
		}
	}

	hash, err := security.HashPIN(pin)
	if err != nil {
		return err
	}
	username := "team:" + strings.TrimSpace(locationNumber) + ":" + strings.TrimSpace(timePunchName)
	_, err = s.exec(ctx, `
		INSERT INTO users (username, password_hash, is_admin, role, access_level, location_number, time_punch_name, created_at)
		VALUES (@username, @password_hash, 0, @role, @access_level, @location_number, @time_punch_name, @created_at)
		ON CONFLICT(username)
		DO UPDATE SET
			password_hash = excluded.password_hash,
			is_admin = 0,
			role = excluded.role,
			access_level = CASE
				WHEN TRIM(COALESCE(users.access_level, '')) = '' THEN excluded.access_level
				ELSE users.access_level
			END,
			location_number = excluded.location_number,
			time_punch_name = excluded.time_punch_name;
	`, map[string]string{
		"username":        username,
		"password_hash":   hash,
		"role":            userRoleTeam,
		"access_level":    teamAccessLevelNoAccess,
		"location_number": strings.TrimSpace(locationNumber),
		"time_punch_name": strings.TrimSpace(timePunchName),
		"created_at":      strconv.FormatInt(time.Now().UTC().Unix(), 10),
	})
	return err
}

func normalizeTeamAccessLevel(raw string) (string, error) {
	level := strings.ToLower(strings.TrimSpace(raw))
	switch level {
	case teamAccessLevelNoAccess:
		return level, nil
	default:
		return "", errors.New("invalid team access level")
	}
}

func (s *sqliteStore) updateTeamMemberAccessLevel(ctx context.Context, locationNumber, timePunchName, accessLevel string) error {
	normalized, err := normalizeTeamAccessLevel(accessLevel)
	if err != nil {
		return err
	}
	if _, _, err := s.lookupTeamUserByLocationAndTimePunch(ctx, strings.TrimSpace(locationNumber), strings.TrimSpace(timePunchName)); err != nil {
		return err
	}
	_, err = s.exec(ctx, `
		UPDATE users
		SET access_level = @access_level
		WHERE role = @role
			AND location_number = @location_number
			AND time_punch_name = @time_punch_name;
	`, map[string]string{
		"access_level":    normalized,
		"role":            userRoleTeam,
		"location_number": strings.TrimSpace(locationNumber),
		"time_punch_name": strings.TrimSpace(timePunchName),
	})
	return err
}

func (s *sqliteStore) upsertRestaurantUser(ctx context.Context, locationNumber, username, password string) error {
	hash, err := security.HashPassword(password)
	if err != nil {
		return err
	}
	username = strings.TrimSpace(username)
	locationNumber = strings.TrimSpace(locationNumber)
	_, err = s.exec(ctx, `
		DELETE FROM users
		WHERE role = @role
			AND location_number = @location_number;
		INSERT INTO users (username, password_hash, is_admin, role, access_level, location_number, time_punch_name, created_at)
		VALUES (@username, @password_hash, 0, @role, @access_level, @location_number, '', @created_at)
		ON CONFLICT(username)
		DO UPDATE SET
			password_hash = excluded.password_hash,
			is_admin = 0,
			role = excluded.role,
			access_level = excluded.access_level,
			location_number = excluded.location_number,
			time_punch_name = '';
	`, map[string]string{
		"username":        username,
		"password_hash":   hash,
		"role":            userRoleRestaurant,
		"access_level":    teamAccessLevelNoAccess,
		"location_number": locationNumber,
		"created_at":      strconv.FormatInt(time.Now().UTC().Unix(), 10),
	})
	return err
}

func (s *sqliteStore) deleteRestaurantUsersForLocation(ctx context.Context, locationNumber string) error {
	_, err := s.exec(ctx, `
		DELETE FROM users
		WHERE role = @role
			AND location_number = @location_number;
	`, map[string]string{
		"role":            userRoleRestaurant,
		"location_number": strings.TrimSpace(locationNumber),
	})
	return err
}

func (s *sqliteStore) deleteOtherRestaurantUsersForLocation(ctx context.Context, locationNumber, username string) error {
	_, err := s.exec(ctx, `
		DELETE FROM users
		WHERE role = @role
			AND location_number = @location_number
			AND username != @username;
	`, map[string]string{
		"role":            userRoleRestaurant,
		"location_number": strings.TrimSpace(locationNumber),
		"username":        strings.TrimSpace(username),
	})
	return err
}

func (s *sqliteStore) restaurantUserExists(ctx context.Context, locationNumber, username string) (bool, error) {
	rows, err := s.query(ctx, `
		SELECT COUNT(*) AS count
		FROM users
		WHERE role = @role
			AND location_number = @location_number
			AND username = @username;
	`, map[string]string{
		"role":            userRoleRestaurant,
		"location_number": strings.TrimSpace(locationNumber),
		"username":        strings.TrimSpace(username),
	})
	if err != nil {
		return false, err
	}
	if len(rows) == 0 {
		return false, nil
	}
	count, err := valueAsInt64(rows[0]["count"])
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func (s *sqliteStore) createSession(ctx context.Context, id string, userID int64, csrfToken string, expiresAt time.Time) error {
	now := time.Now().UTC().Unix()
	_, err := s.exec(ctx, `
		INSERT INTO sessions (id, user_id, csrf_token, expires_at, created_at, last_seen_at)
		VALUES (@id, @user_id, @csrf_token, @expires_at, @created_at, @last_seen_at);
	`, map[string]string{
		"id":           id,
		"user_id":      strconv.FormatInt(userID, 10),
		"csrf_token":   csrfToken,
		"expires_at":   strconv.FormatInt(expiresAt.UTC().Unix(), 10),
		"created_at":   strconv.FormatInt(now, 10),
		"last_seen_at": strconv.FormatInt(now, 10),
	})
	return err
}

func (s *sqliteStore) lookupSession(ctx context.Context, id string) (*sessionRecord, *userRecord, error) {
	rows, err := s.query(ctx, `
		SELECT s.id, s.user_id, s.csrf_token, s.expires_at, u.username, u.is_admin, u.role, u.access_level, u.location_number, u.time_punch_name
		FROM sessions s
		INNER JOIN users u ON u.id = s.user_id
		WHERE s.id = @id
		LIMIT 1;
	`, map[string]string{"id": id})
	if err != nil {
		return nil, nil, err
	}
	if len(rows) == 0 {
		return nil, nil, errNotFound
	}

	userID, err := valueAsInt64(rows[0]["user_id"])
	if err != nil {
		return nil, nil, err
	}
	expiresUnix, err := valueAsInt64(rows[0]["expires_at"])
	if err != nil {
		return nil, nil, err
	}
	expiresAt := time.Unix(expiresUnix, 0).UTC()
	if time.Now().UTC().After(expiresAt) {
		_ = s.deleteSession(ctx, id)
		return nil, nil, errNotFound
	}

	sessionID, err := valueAsString(rows[0]["id"])
	if err != nil {
		return nil, nil, err
	}
	csrfToken, err := valueAsString(rows[0]["csrf_token"])
	if err != nil {
		return nil, nil, err
	}
	username, err := valueAsString(rows[0]["username"])
	if err != nil {
		return nil, nil, err
	}
	isAdminRaw, err := valueAsInt64(rows[0]["is_admin"])
	if err != nil {
		return nil, nil, err
	}
	role, err := valueAsString(rows[0]["role"])
	if err != nil {
		return nil, nil, err
	}
	accessLevel, err := valueAsString(rows[0]["access_level"])
	if err != nil {
		return nil, nil, err
	}
	locationNumber, err := valueAsString(rows[0]["location_number"])
	if err != nil {
		return nil, nil, err
	}
	timePunchName, err := valueAsString(rows[0]["time_punch_name"])
	if err != nil {
		return nil, nil, err
	}

	_, _ = s.exec(ctx, `UPDATE sessions SET last_seen_at = @last_seen_at WHERE id = @id;`, map[string]string{
		"last_seen_at": strconv.FormatInt(time.Now().UTC().Unix(), 10),
		"id":           id,
	})

	return &sessionRecord{ID: sessionID, UserID: userID, CSRFToken: csrfToken, ExpiresAt: expiresAt}, &userRecord{
		ID:             userID,
		Username:       username,
		IsAdmin:        isAdminRaw == 1,
		Role:           strings.TrimSpace(role),
		AccessLevel:    strings.TrimSpace(accessLevel),
		LocationNumber: strings.TrimSpace(locationNumber),
		TimePunchName:  strings.TrimSpace(timePunchName),
	}, nil
}

func (s *sqliteStore) deleteSession(ctx context.Context, id string) error {
	_, err := s.exec(ctx, `DELETE FROM sessions WHERE id = @id;`, map[string]string{"id": id})
	return err
}

func (s *sqliteStore) exec(ctx context.Context, statement string, params map[string]string) (string, error) {
	return s.run(ctx, statement, params, false)
}

func (s *sqliteStore) query(ctx context.Context, statement string, params map[string]string) ([]map[string]any, error) {
	out, err := s.run(ctx, statement, params, true)
	if err != nil {
		return nil, err
	}
	trimmed := strings.TrimSpace(out)
	if trimmed == "" {
		return []map[string]any{}, nil
	}

	var rows []map[string]any
	if err := json.Unmarshal([]byte(trimmed), &rows); err != nil {
		return nil, err
	}
	return rows, nil
}

func (s *sqliteStore) run(ctx context.Context, statement string, params map[string]string, jsonMode bool) (string, error) {
	runCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()

	boundSQL := bindSQLParams(statement, params)
	var script strings.Builder
	script.WriteString(".timeout 5000\n")
	if jsonMode {
		script.WriteString(".mode json\n")
	}
	script.WriteString("PRAGMA foreign_keys = ON;\n")
	script.WriteString(boundSQL)
	if !strings.HasSuffix(boundSQL, "\n") {
		script.WriteString("\n")
	}

	cmd := exec.CommandContext(runCtx, "sqlite3", s.dbPath)
	cmd.Stdin = strings.NewReader(script.String())
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("sqlite3 command failed: %w (%s)", err, strings.TrimSpace(string(output)))
	}
	return string(output), nil
}

func bindSQLParams(statement string, params map[string]string) string {
	if len(params) == 0 {
		return statement
	}
	keys := make([]string, 0, len(params))
	for key := range params {
		keys = append(keys, key)
	}
	// Replace longer keys first to avoid partial-token replacement collisions.
	sort.Slice(keys, func(i, j int) bool {
		return len(keys[i]) > len(keys[j])
	})
	result := statement
	for _, key := range keys {
		result = strings.ReplaceAll(result, "@"+key, sqliteStringLiteral(params[key]))
	}
	return result
}

func withSQLiteRetry(fn func() error) error {
	const maxAttempts = 3
	var err error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		err = fn()
		if err == nil {
			return nil
		}
		lower := strings.ToLower(err.Error())
		if !strings.Contains(lower, "database is locked") && !strings.Contains(lower, "database is busy") {
			return err
		}
		if attempt < maxAttempts {
			time.Sleep(time.Duration(attempt) * 125 * time.Millisecond)
		}
	}
	return err
}

func userFromContext(ctx context.Context) *userRecord {
	raw := ctx.Value(userContextKey)
	record, ok := raw.(*userRecord)
	if !ok {
		return nil
	}
	return record
}

func sessionFromContext(ctx context.Context) *sessionRecord {
	raw := ctx.Value(sessionContextKey)
	record, ok := raw.(*sessionRecord)
	if !ok {
		return nil
	}
	return record
}

func userRoleOrDefault(role string, isAdmin bool) string {
	trimmed := strings.TrimSpace(strings.ToLower(role))
	if trimmed != "" {
		return trimmed
	}
	if isAdmin {
		return userRoleAdmin
	}
	return userRoleRestaurant
}

func isAdminUser(ctx context.Context) bool {
	record := userFromContext(ctx)
	if record == nil {
		return false
	}
	return record.IsAdmin || userRoleOrDefault(record.Role, record.IsAdmin) == userRoleAdmin
}

func userCanAccessLocation(record *userRecord, locationNumber string) bool {
	if record == nil {
		return false
	}
	if record.IsAdmin || userRoleOrDefault(record.Role, record.IsAdmin) == userRoleAdmin {
		return true
	}
	return strings.TrimSpace(record.LocationNumber) == strings.TrimSpace(locationNumber)
}

func randomToken(bytesLen int) (string, error) {
	buf := make([]byte, bytesLen)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func generateReadablePassword(length int) (string, error) {
	if length <= 0 {
		length = 12
	}
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*"
	raw := make([]byte, length)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	out := make([]byte, length)
	for i := 0; i < length; i++ {
		out[i] = alphabet[int(raw[i])%len(alphabet)]
	}
	return string(out), nil
}

func locationLoginEmail(number string) string {
	trimmed := strings.TrimSpace(number)
	if trimmed == "" {
		return ""
	}
	return strings.ToLower(trimmed) + "@chick-fil-a.com"
}

func locationDefaultPassword(number string) string {
	return strings.TrimSpace(number) + "wafflefry!"
}

func validateCreateLocation(req createLocationRequest) error {
	name := strings.TrimSpace(req.Name)
	number := strings.TrimSpace(req.Number)
	email := strings.TrimSpace(req.Email)
	phone := strings.TrimSpace(req.Phone)
	employerRepSignature := strings.TrimSpace(req.EmployerRepSignature)
	businessName := strings.TrimSpace(req.BusinessName)
	businessStreet := strings.TrimSpace(req.BusinessStreet)
	businessCity := strings.TrimSpace(req.BusinessCity)
	businessState := strings.TrimSpace(req.BusinessState)
	businessEIN := strings.TrimSpace(req.BusinessEIN)
	if businessStreet == "" && businessCity == "" && businessState == "" {
		businessStreet, businessCity, businessState = splitBusinessAddressParts(req.BusinessAddress)
	}
	if name == "" {
		return errors.New("name is required")
	}
	if number == "" {
		return errors.New("number is required")
	}
	if email == "" {
		return errors.New("email is required")
	}
	if phone == "" {
		return errors.New("phone is required")
	}
	if employerRepSignature == "" {
		return errors.New("owner/operator is required")
	}
	if businessName == "" {
		return errors.New("business or organization name is required")
	}
	if businessStreet == "" {
		return errors.New("business street is required")
	}
	if businessCity == "" {
		return errors.New("business city is required")
	}
	if businessState == "" {
		return errors.New("business state is required")
	}
	if businessEIN == "" {
		return errors.New("business EIN is required")
	}
	if len([]rune(businessName)) > 160 {
		return errors.New("business or organization name must be 160 characters or fewer")
	}
	if len([]rune(businessStreet)) > 180 {
		return errors.New("business street must be 180 characters or fewer")
	}
	if len([]rune(businessCity)) > 100 {
		return errors.New("business city must be 100 characters or fewer")
	}
	if len([]rune(businessState)) > 60 {
		return errors.New("business state must be 60 characters or fewer")
	}
	if len([]rune(businessEIN)) > 32 {
		return errors.New("business EIN must be 32 characters or fewer")
	}
	if len([]rune(email)) > 200 {
		return errors.New("email must be 200 characters or fewer")
	}
	if len([]rune(phone)) > 40 {
		return errors.New("phone must be 40 characters or fewer")
	}
	if !strings.Contains(email, "@") {
		return errors.New("email must be a valid email address")
	}
	if len([]rune(employerRepSignature)) > 120 {
		return errors.New("owner/operator must be 120 characters or fewer")
	}
	validNumber := regexp.MustCompile(`^[A-Za-z0-9-]+$`)
	if !validNumber.MatchString(number) {
		return errors.New("number can only contain letters, digits, and hyphens")
	}
	return nil
}

func validateCreateTimePunchEntry(req createTimePunchEntryRequest) error {
	if strings.TrimSpace(req.TimePunchName) == "" {
		return errors.New("employee is required")
	}
	if _, err := time.Parse("2006-01-02", strings.TrimSpace(req.PunchDate)); err != nil {
		return errors.New("date must use YYYY-MM-DD")
	}
	if _, err := time.Parse("15:04", strings.TrimSpace(req.TimeIn)); err != nil {
		return errors.New("time in must use HH:MM")
	}
	if _, err := time.Parse("15:04", strings.TrimSpace(req.TimeOut)); err != nil {
		return errors.New("time out must use HH:MM")
	}
	if len([]rune(strings.TrimSpace(req.Note))) > 255 {
		return errors.New("note must be 255 characters or fewer")
	}
	return nil
}

func validateCreateTimeOffRequest(req createTimeOffRequestRequest) (string, string, error) {
	req.TimePunchName = strings.TrimSpace(req.TimePunchName)
	start := strings.TrimSpace(req.StartDate)
	end := strings.TrimSpace(req.EndDate)
	if req.TimePunchName == "" {
		return "", "", errors.New("employee is required")
	}
	startDate, err := time.Parse("2006-01-02", start)
	if err != nil {
		return "", "", errors.New("start date must use YYYY-MM-DD")
	}
	endDate := startDate
	if end != "" {
		parsedEnd, err := time.Parse("2006-01-02", end)
		if err != nil {
			return "", "", errors.New("end date must use YYYY-MM-DD")
		}
		endDate = parsedEnd
	}
	if endDate.Before(startDate) {
		return "", "", errors.New("end date cannot be before start date")
	}
	return startDate.Format("2006-01-02"), endDate.Format("2006-01-02"), nil
}

func validateCreateUniformOrder(req createUniformOrderRequest) error {
	if strings.TrimSpace(req.TimePunchName) == "" {
		return errors.New("employee is required")
	}
	if len(req.Items) == 0 {
		return errors.New("at least one item must be selected")
	}
	for _, item := range req.Items {
		orderType := strings.ToLower(strings.TrimSpace(item.OrderType))
		if orderType == uniformSystemKeyShoes {
			if !shoeStylePattern.MatchString(strings.TrimSpace(item.ShoeItemNumber)) {
				return errors.New("shoe style number must be exactly 5 digits")
			}
			if strings.TrimSpace(item.ShoePrice) == "" {
				return errors.New("shoe price is required")
			}
		} else if item.ItemID <= 0 {
			return errors.New("invalid item selection")
		}
		if item.Quantity <= 0 {
			return errors.New("quantity must be at least 1")
		}
		if len(strings.TrimSpace(item.Note)) > 500 {
			return errors.New("note must be 500 characters or fewer")
		}
	}
	return nil
}

func parsePriceToCents(value string) (int64, error) {
	trimmed := strings.TrimSpace(strings.TrimPrefix(value, "$"))
	if trimmed == "" {
		return 0, errors.New("price is required")
	}
	parsed, err := strconv.ParseFloat(trimmed, 64)
	if err != nil || parsed < 0 {
		return 0, errors.New("price must be a non-negative number")
	}
	cents := int64(parsed*100 + 0.5)
	return cents, nil
}

func boolToInt64(value bool) int64 {
	if value {
		return 1
	}
	return 0
}

func parseUniformSizes(raw string) []string {
	parts := strings.Split(raw, ",")
	sizes := make([]string, 0, len(parts))
	seen := map[string]struct{}{}
	for _, part := range parts {
		size := strings.TrimSpace(part)
		if size == "" {
			continue
		}
		key := strings.ToLower(size)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		sizes = append(sizes, size)
	}
	return sizes
}

func legacyUniformSizeFields(sizes []string) []uniformSizeField {
	if len(sizes) == 0 {
		return nil
	}
	return []uniformSizeField{
		{
			Label:   "Size",
			Options: sizes,
		},
	}
}

func flattenUniformSizeFields(fields []uniformSizeField) []string {
	if len(fields) == 0 {
		return nil
	}
	options := make([]string, 0, len(fields[0].Options))
	for _, option := range fields[0].Options {
		option = strings.TrimSpace(option)
		if option == "" {
			continue
		}
		options = append(options, option)
	}
	return options
}

func parseUniformSizeFields(raw string) ([]uniformSizeField, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	fields := make([]uniformSizeField, 0)
	seenLabels := map[string]struct{}{}
	addField := func(label string, options []string) error {
		label = strings.TrimSpace(label)
		if label == "" {
			return errors.New("size field label is required")
		}
		if len(label) > 60 {
			return fmt.Errorf("size field label %q must be 60 characters or fewer", label)
		}
		key := strings.ToLower(label)
		if _, exists := seenLabels[key]; exists {
			return fmt.Errorf("duplicate size field label %q", label)
		}
		seenLabels[key] = struct{}{}
		if len(options) == 0 {
			return fmt.Errorf("size field %q must include at least one option", label)
		}
		cleanOptions := make([]string, 0, len(options))
		seenOptions := map[string]struct{}{}
		for _, option := range options {
			option = strings.TrimSpace(option)
			if option == "" {
				continue
			}
			if len(option) > 60 {
				return fmt.Errorf("size option %q must be 60 characters or fewer", option)
			}
			optionKey := strings.ToLower(option)
			if _, exists := seenOptions[optionKey]; exists {
				continue
			}
			seenOptions[optionKey] = struct{}{}
			cleanOptions = append(cleanOptions, option)
		}
		if len(cleanOptions) == 0 {
			return fmt.Errorf("size field %q must include at least one option", label)
		}
		fields = append(fields, uniformSizeField{Label: label, Options: cleanOptions})
		return nil
	}

	if strings.HasPrefix(raw, "[") {
		var parsed []uniformSizeField
		if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
			return nil, errors.New("size fields must be valid JSON")
		}
		for _, field := range parsed {
			if err := addField(field.Label, field.Options); err != nil {
				return nil, err
			}
		}
		return fields, nil
	}

	lines := strings.Split(raw, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		label := ""
		optionsRaw := ""
		if strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			label = strings.TrimSpace(parts[0])
			optionsRaw = strings.TrimSpace(parts[1])
		} else {
			label = "Size"
			optionsRaw = line
		}
		options := parseUniformSizes(optionsRaw)
		if err := addField(label, options); err != nil {
			return nil, err
		}
	}
	return fields, nil
}

func normalizeUniformSizeFieldsInput(rawFields, legacySizes string) ([]uniformSizeField, error) {
	fields, err := parseUniformSizeFields(rawFields)
	if err != nil {
		return nil, err
	}
	if len(fields) > 0 {
		return fields, nil
	}
	return legacyUniformSizeFields(parseUniformSizes(legacySizes)), nil
}

func normalizeSizeSelections(in map[string]string) map[string]string {
	if len(in) == 0 {
		return map[string]string{}
	}
	out := make(map[string]string, len(in))
	for key, value := range in {
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key == "" || value == "" {
			continue
		}
		out[key] = value
	}
	return out
}

func normalizeSizeValues(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, value := range in {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		out = append(out, trimmed)
	}
	return out
}

func buildUniformSizeOption(fields []uniformSizeField, selections map[string]string) (string, error) {
	if len(fields) == 0 {
		return "", nil
	}
	remaining := normalizeSizeSelections(selections)
	parts := make([]string, 0, len(fields))
	for _, field := range fields {
		selected := ""
		selectedKey := ""
		for key, value := range remaining {
			if strings.EqualFold(strings.TrimSpace(key), strings.TrimSpace(field.Label)) {
				selected = strings.TrimSpace(value)
				selectedKey = key
				break
			}
		}
		if selected == "" {
			return "", fmt.Errorf("%s is required", strings.TrimSpace(field.Label))
		}
		matched := ""
		for _, option := range field.Options {
			if strings.EqualFold(strings.TrimSpace(option), selected) {
				matched = option
				break
			}
		}
		if matched == "" {
			// Accept posted value as-is to tolerate option drift between UI and server state.
			matched = selected
		}
		parts = append(parts, strings.TrimSpace(field.Label)+": "+matched)
		delete(remaining, selectedKey)
	}
	for key := range remaining {
		if strings.TrimSpace(key) != "" {
			return "", errors.New("invalid size selection")
		}
	}
	return strings.Join(parts, ", "), nil
}

func containsIgnoreCase(values []string, target string) bool {
	target = strings.TrimSpace(strings.ToLower(target))
	for _, value := range values {
		if strings.TrimSpace(strings.ToLower(value)) == target {
			return true
		}
	}
	return false
}

func resolveBusinessDayDatesForCreate(req createBusinessDayRequest) ([]string, error) {
	parseDate := func(value string) (time.Time, error) {
		return time.Parse("2006-01-02", strings.TrimSpace(value))
	}

	// Backward-compatible single-date support.
	if req.BusinessDate != "" {
		day, err := parseDate(req.BusinessDate)
		if err != nil {
			return nil, errors.New("business date must use YYYY-MM-DD")
		}
		if day.Weekday() == time.Sunday {
			return nil, errors.New("sunday cannot be created as a business day")
		}
		return []string{day.Format("2006-01-02")}, nil
	}

	if req.StartDate == "" {
		return nil, errors.New("start date is required")
	}
	start, err := parseDate(req.StartDate)
	if err != nil {
		return nil, errors.New("start date must use YYYY-MM-DD")
	}
	end := start
	if req.EndDate != "" {
		end, err = parseDate(req.EndDate)
		if err != nil {
			return nil, errors.New("end date must use YYYY-MM-DD")
		}
	}
	if end.Before(start) {
		return nil, errors.New("end date must be on or after start date")
	}

	dates := make([]string, 0, int(end.Sub(start).Hours()/24)+1)
	for day := start; !day.After(end); day = day.AddDate(0, 0, 1) {
		if day.Weekday() == time.Sunday {
			continue
		}
		dates = append(dates, day.Format("2006-01-02"))
	}
	if len(dates) == 0 {
		return nil, errors.New("range must include at least one non-sunday date")
	}
	return dates, nil
}

func validateUpdateBusinessDay(req updateBusinessDayRequest) (float64, float64, error) {
	totalSales, err := strconv.ParseFloat(strings.TrimSpace(req.TotalSales), 64)
	if err != nil || totalSales < 0 {
		return 0, 0, errors.New("total sales must be a non-negative number")
	}
	laborHours, err := strconv.ParseFloat(strings.TrimSpace(req.LaborHours), 64)
	if err != nil || laborHours < 0 {
		return 0, 0, errors.New("labor hours must be a non-negative number")
	}
	return totalSales, laborHours, nil
}

func validateBusinessDateString(value string) error {
	parsed, err := time.Parse("2006-01-02", strings.TrimSpace(value))
	if err != nil {
		return errors.New("business date must use YYYY-MM-DD")
	}
	if parsed.Weekday() == time.Sunday {
		return errors.New("sunday cannot be used as a business day")
	}
	return nil
}

func parsePositiveInt(raw string, fallback int) int {
	if strings.TrimSpace(raw) == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value <= 0 {
		return fallback
	}
	return value
}

func parseDepartmentsCSV(raw string) []string {
	return sanitizeDepartments(strings.Split(raw, ","))
}

func sanitizeDepartments(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values)+1)
	for _, value := range values {
		department := strings.ToUpper(strings.TrimSpace(value))
		if department == "" {
			continue
		}
		if _, exists := seen[department]; exists {
			continue
		}
		seen[department] = struct{}{}
		out = append(out, department)
	}
	if _, exists := seen["INIT"]; exists {
		reordered := []string{"INIT"}
		for _, department := range out {
			if department == "INIT" {
				continue
			}
			reordered = append(reordered, department)
		}
		return reordered
	}
	return append([]string{"INIT"}, out...)
}

func departmentsSet(values []string) map[string]struct{} {
	departments := sanitizeDepartments(values)
	set := make(map[string]struct{}, len(departments))
	for _, department := range departments {
		set[department] = struct{}{}
	}
	return set
}

func normalizeDepartment(value string) string {
	dept := strings.ToUpper(strings.TrimSpace(value))
	if dept == "" {
		return "INIT"
	}
	return dept
}

func jobHasDepartment(job *locationJob, departmentID int64) bool {
	if job == nil || departmentID <= 0 {
		return false
	}
	for _, id := range job.DepartmentIDs {
		if id == departmentID {
			return true
		}
	}
	return job.DepartmentID == departmentID
}

func departmentNameByID(departments []locationDepartment, departmentID int64) string {
	for _, department := range departments {
		if department.ID == departmentID {
			return strings.TrimSpace(department.Name)
		}
	}
	return ""
}

func normalizeLetterGrade(value string) string {
	normalized := strings.ToUpper(strings.TrimSpace(value))
	switch normalized {
	case "A", "B", "C", "D", "F":
		return normalized
	default:
		return ""
	}
}

func letterGradeScore(letter string) float64 {
	switch normalizeLetterGrade(letter) {
	case "A":
		return 4
	case "B":
		return 3
	case "C":
		return 2
	case "D":
		return 1
	default:
		return 0
	}
}

func (s *server) resolveInterviewNameForLocation(ctx context.Context, locationNumber, raw string) (string, error) {
	target := strings.TrimSpace(raw)
	if target == "" {
		return "", nil
	}
	names, err := s.store.listCandidateInterviewNames(ctx, locationNumber)
	if err != nil {
		return "", err
	}
	for _, name := range names {
		if strings.EqualFold(strings.TrimSpace(name.Name), target) {
			return name.Name, nil
		}
	}
	return "", nil
}

func (s *server) resolveInterviewNameByIDForLocation(ctx context.Context, locationNumber string, interviewNameID int64) (string, error) {
	if interviewNameID <= 0 {
		return "", nil
	}
	names, err := s.store.listCandidateInterviewNames(ctx, locationNumber)
	if err != nil {
		return "", err
	}
	for _, name := range names {
		if name.ID == interviewNameID {
			return strings.TrimSpace(name.Name), nil
		}
	}
	return "", nil
}

func (s *server) resolveInterviewNameIDForLocation(ctx context.Context, locationNumber, raw string) (int64, error) {
	target := strings.TrimSpace(raw)
	if target == "" {
		return 0, nil
	}
	names, err := s.store.listCandidateInterviewNames(ctx, locationNumber)
	if err != nil {
		return 0, err
	}
	for _, name := range names {
		if strings.EqualFold(strings.TrimSpace(name.Name), target) {
			return name.ID, nil
		}
	}
	return 0, nil
}

func (s *server) resolveInterviewInterviewer(ctx context.Context, locationNumber, requested string) (string, error) {
	requested = strings.TrimSpace(requested)
	if requested == "" {
		return "", errors.New("interviewer is required")
	}
	if _, err := s.store.getLocationEmployee(ctx, locationNumber, requested); err == nil {
		return requested, nil
	}
	employeeCount, err := s.store.countEmployeesForLocation(ctx, locationNumber)
	if err != nil {
		return "", err
	}
	if employeeCount > 0 {
		return "", errors.New("interviewer must be an active employee in this location")
	}
	settings, err := s.store.getLocationSettings(ctx, locationNumber)
	if err != nil {
		return "", err
	}
	ownerOperator := strings.TrimSpace(settings.EmployerRepSignature)
	if ownerOperator == "" {
		ownerOperator = "Owner/Operator"
	}
	if strings.EqualFold(requested, ownerOperator) || strings.EqualFold(requested, "owner/operator") {
		return ownerOperator, nil
	}
	return "", errors.New("interviewer must be owner/operator until first employee is hired")
}

func candidateAverageGradePercent(interviews []candidateInterview) float64 {
	var total float64
	var count int
	for _, interview := range interviews {
		for _, grade := range interview.Grades {
			total += grade.Score
			count++
		}
	}
	if count == 0 {
		return 0
	}
	return (total / float64(count)) * 100
}

func parseBioEmployeesFromSpreadsheet(reader io.Reader, filename string) ([]bioEmployeeRow, error) {
	rows, err := readRowsFromSpreadsheet(reader, filename)
	if err != nil {
		return nil, err
	}

	headerIndex := map[string]int{}
	for i, header := range rows[0] {
		headerIndex[normalizeHeader(header)] = i
	}

	nameIdx, ok := headerIndex["employee name"]
	if !ok {
		return nil, fmt.Errorf("missing required column: employee name")
	}
	employeeNumberIdx := -1
	if idx, ok := headerIndex["employee number"]; ok {
		employeeNumberIdx = idx
	}
	statusIdx := -1
	if idx, ok := headerIndex["employee status"]; ok {
		statusIdx = idx
	}
	termDateIdx := -1
	if idx, ok := headerIndex["termination date"]; ok {
		termDateIdx = idx
	}

	var employees []bioEmployeeRow
	for _, row := range rows[1:] {
		name := cellValue(row, nameIdx)
		first, last, timePunch, ok := splitTimePunchName(name)
		if !ok {
			continue
		}
		status := strings.ToLower(strings.TrimSpace(cellValue(row, statusIdx)))
		termDate := strings.TrimSpace(cellValue(row, termDateIdx))
		terminated := termDate != "" || strings.Contains(status, "terminat") || strings.Contains(status, "inactive")
		employees = append(employees, bioEmployeeRow{
			EmployeeNumber: strings.TrimSpace(cellValue(row, employeeNumberIdx)),
			FirstName:      first,
			LastName:       last,
			TimePunchName:  timePunch,
			Terminated:     terminated,
		})
	}

	return employees, nil
}

func parseBirthdatesFromSpreadsheet(reader io.Reader, filename string) ([]birthdateRow, error) {
	rows, err := readRowsFromSpreadsheet(reader, filename)
	if err != nil {
		return nil, err
	}

	headerIndex := map[string]int{}
	for i, header := range rows[0] {
		headerIndex[normalizeHeader(header)] = i
	}

	nameIdx, ok := headerIndex["employee name"]
	if !ok {
		return nil, fmt.Errorf("missing required column: employee name")
	}

	birthIdx := -1
	if idx, ok := headerIndex["birth date"]; ok {
		birthIdx = idx
	}
	if idx, ok := headerIndex["birthdate"]; ok && birthIdx == -1 {
		birthIdx = idx
	}
	if idx, ok := headerIndex["birthday"]; ok && birthIdx == -1 {
		birthIdx = idx
	}
	if birthIdx == -1 {
		return nil, fmt.Errorf("missing required column: birth date")
	}

	var rowsOut []birthdateRow
	for _, row := range rows[1:] {
		name := cellValue(row, nameIdx)
		_, _, timePunch, ok := splitTimePunchName(name)
		if !ok {
			continue
		}
		birthday := cellValue(row, birthIdx)
		normalizedBirthday, ok := normalizeBirthday(birthday)
		if !ok {
			normalizedBirthday, ok = findBirthdayInRow(row, birthIdx)
		}
		if !ok {
			continue
		}
		rowsOut = append(rowsOut, birthdateRow{
			TimePunchName: timePunch,
			Birthday:      normalizedBirthday,
		})
	}

	return rowsOut, nil
}

func findBirthdayInRow(row []string, skipIdx int) (string, bool) {
	for idx, cell := range row {
		if idx == skipIdx {
			continue
		}
		if normalized, ok := normalizeBirthday(cell); ok {
			return normalized, true
		}
	}
	return "", false
}

func readRowsFromSpreadsheet(reader io.Reader, filename string) ([][]string, error) {
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}

	ext := strings.ToLower(filepath.Ext(filename))
	switch ext {
	case ".xls", ".xsl":
		workbook, err := xls.OpenReader(bytes.NewReader(data), "utf-8")
		if err != nil {
			return nil, err
		}
		if workbook.NumSheets() == 0 {
			return nil, fmt.Errorf("no worksheet found")
		}
		if workbook.NumSheets() > 1 {
			return nil, fmt.Errorf("multiple worksheets found; please upload a file with a single sheet")
		}
		rows := workbook.ReadAllCells(100000)
		if len(rows) == 0 {
			return nil, fmt.Errorf("worksheet is empty")
		}
		return rows, nil
	default:
		file, err := excelize.OpenReader(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		defer func() { _ = file.Close() }()

		sheetName := file.GetSheetName(0)
		if sheetName == "" {
			return nil, fmt.Errorf("no worksheet found")
		}

		rows, err := file.GetRows(sheetName)
		if err != nil {
			return nil, err
		}
		if len(rows) == 0 {
			return nil, fmt.Errorf("worksheet is empty")
		}
		return rows, nil
	}
}

func normalizeHeader(header string) string {
	return strings.ToLower(strings.TrimSpace(header))
}

func cellValue(row []string, idx int) string {
	if idx < 0 || idx >= len(row) {
		return ""
	}
	return strings.TrimSpace(row[idx])
}

func splitTimePunchName(name string) (string, string, string, bool) {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return "", "", "", false
	}

	if strings.Contains(trimmed, ",") {
		parts := strings.SplitN(trimmed, ",", 2)
		last := strings.TrimSpace(parts[0])
		first := strings.TrimSpace(parts[1])
		if first == "" || last == "" {
			return "", "", "", false
		}
		return first, last, canonicalTimePunchName(first, last), true
	}

	fields := strings.Fields(trimmed)
	if len(fields) < 2 {
		return "", "", "", false
	}
	first := fields[0]
	last := fields[len(fields)-1]
	return first, last, canonicalTimePunchName(first, last), true
}

func canonicalTimePunchName(firstName, lastName string) string {
	return strings.ToLower(strings.TrimSpace(lastName)) + ", " + strings.ToLower(strings.TrimSpace(firstName))
}

// uniqueTimePunchNameForLocation returns a time punch name that is guaranteed to
// be unused within the given location. If the canonical "lastname, firstname" is
// already taken by an active employee, it appends a numeric suffix so that
// multiple employees who share a name can coexist:
//
//	doe, john
//	doe, john (2)
//	doe, john (3)  …
func (s *server) uniqueTimePunchNameForLocation(ctx context.Context, locationNumber, firstName, lastName string) (string, error) {
	base := canonicalTimePunchName(firstName, lastName)
	if _, err := s.store.getLocationEmployee(ctx, locationNumber, base); errors.Is(err, errNotFound) {
		return base, nil
	} else if err != nil {
		return "", err
	}
	for n := 2; n <= 999; n++ {
		candidate := fmt.Sprintf("%s (%d)", base, n)
		if _, err := s.store.getLocationEmployee(ctx, locationNumber, candidate); errors.Is(err, errNotFound) {
			return candidate, nil
		} else if err != nil {
			return "", err
		}
	}
	return "", errors.New("unable to generate a unique employee time punch name")
}

func normalizeBirthday(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", false
	}

	// Excel numeric date serial (common in XLS/XLSX exports).
	if serial, err := strconv.ParseFloat(value, 64); err == nil {
		// Keep a realistic birthday serial range to avoid treating plain years as serial dates.
		if serial >= 20000 && serial <= 80000 {
			if parsed, err := excelize.ExcelDateToTime(serial, false); err == nil {
				return parsed.Format("2006-01-02"), true
			}
		}
	}

	dateFormats := []string{
		"2006-01-02",
		"1/2/2006",
		"01/02/2006",
		"1/2/06",
		"01/02/06",
		"1-2-2006",
		"01-02-2006",
		"1-2-06",
		"01-02-06",
		"Jan 2, 2006",
		"January 2, 2006",
		"2 Jan 2006",
		"2 January 2006",
		"2006/01/02",
		"1/2/2006 3:04 PM",
		"01/02/2006 03:04 PM",
		"1/2/2006 3:04:05 PM",
		"01/02/2006 03:04:05 PM",
		"1/2/2006 15:04",
		"01/02/2006 15:04",
		"1/2/2006 15:04:05",
		"01/02/2006 15:04:05",
		"2006-01-02T15:04:05",
	}

	for _, format := range dateFormats {
		if parsed, err := time.Parse(format, value); err == nil {
			return parsed.Format("2006-01-02"), true
		}
	}

	if parsed, err := time.Parse("2006-01-02 15:04:05", value); err == nil {
		return parsed.Format("2006-01-02"), true
	}
	if parsed, err := time.Parse(time.RFC3339, value); err == nil {
		return parsed.Format("2006-01-02"), true
	}

	return "", false
}

func parseAndValidateEmployeePay(payTypeRaw, payAmountRaw string) (string, int64, error) {
	payType := strings.ToLower(strings.TrimSpace(payTypeRaw))
	if payType != "hourly" && payType != "salary" {
		return "", 0, errors.New("pay type must be hourly or salary")
	}
	payAmountRaw = strings.TrimSpace(payAmountRaw)
	if payAmountRaw == "" {
		return "", 0, errors.New("pay amount is required")
	}
	cleaned := strings.ReplaceAll(payAmountRaw, ",", "")
	if strings.HasPrefix(cleaned, "$") {
		cleaned = strings.TrimPrefix(cleaned, "$")
	}
	parsed, err := strconv.ParseFloat(cleaned, 64)
	if err != nil {
		return "", 0, errors.New("pay amount must be a valid number")
	}
	if parsed <= 0 {
		return "", 0, errors.New("pay amount must be greater than zero")
	}
	cents := int64(math.Round(parsed * 100))
	if cents <= 0 {
		return "", 0, errors.New("pay amount must be greater than zero")
	}
	return payType, cents, nil
}

func manualPaperworkRequiredFields(emp *employee) []string {
	if emp == nil {
		return []string{"Employee record"}
	}
	missing := make([]string, 0, 12)
	require := func(value, label string) {
		if strings.TrimSpace(value) == "" {
			missing = append(missing, label)
		}
	}
	require(emp.FirstName, "First Name")
	require(emp.LastName, "Last Name")
	require(emp.TimePunchName, "Time Punch Name")
	require(emp.Department, "Department")
	if emp.JobID <= 0 {
		missing = append(missing, "Pay Band")
	}
	payType := strings.ToLower(strings.TrimSpace(emp.PayType))
	if payType != "hourly" && payType != "salary" {
		missing = append(missing, "Pay Type")
	}
	if emp.PayAmountCents <= 0 {
		missing = append(missing, "Pay Amount")
	}
	if _, ok := normalizeBirthday(emp.Birthday); !ok {
		missing = append(missing, "Birthday")
	}
	require(emp.Email, "Email")
	require(emp.Phone, "Phone")
	require(emp.Address, "Address")
	require(emp.City, "City")
	if normalizeUSStateCode(emp.State) == "" {
		missing = append(missing, "State")
	}
	require(emp.ZipCode, "Zip Code")
	return missing
}

func normalizeNameText(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var b strings.Builder
	lastWasSpace := false
	for _, r := range value {
		if unicode.IsLetter(r) {
			b.WriteRune(r)
			lastWasSpace = false
			continue
		}
		if !lastWasSpace {
			b.WriteByte(' ')
			lastWasSpace = true
		}
	}
	return strings.TrimSpace(b.String())
}

func normalizeInterviewNameIDs(many []int64, single int64) []int64 {
	seen := make(map[int64]struct{}, len(many)+1)
	out := make([]int64, 0, len(many)+1)
	for _, id := range many {
		if id <= 0 {
			continue
		}
		if _, exists := seen[id]; exists {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	if single > 0 {
		if _, exists := seen[single]; !exists {
			out = append(out, single)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func normalizeQuestionResponseType(value string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	switch normalized {
	case questionResponseTypeMultiple, questionResponseTypeNumber:
		return normalized
	default:
		return questionResponseTypeText
	}
}

func normalizeQuestionResponseOptions(options []string) []string {
	out := make([]string, 0, len(options))
	for _, raw := range options {
		option := strings.TrimSpace(raw)
		if option == "" {
			continue
		}
		out = append(out, option)
	}
	return out
}

func hasDuplicateQuestionResponseOptions(options []string) bool {
	seen := make(map[string]struct{}, len(options))
	for _, raw := range options {
		option := strings.TrimSpace(raw)
		if option == "" {
			continue
		}
		key := strings.ToLower(option)
		if _, exists := seen[key]; exists {
			return true
		}
		seen[key] = struct{}{}
	}
	return false
}

func serializeQuestionResponseOptions(options []string) string {
	payload, err := json.Marshal(options)
	if err != nil {
		return "[]"
	}
	return string(payload)
}

func parseQuestionResponseOptions(raw string) []string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return []string{}
	}
	var parsed []string
	if err := json.Unmarshal([]byte(trimmed), &parsed); err == nil {
		return normalizeQuestionResponseOptions(parsed)
	}
	return []string{}
}

func validateCandidateInterviewQuestionDefinition(responseType string, options []string) error {
	if responseType != questionResponseTypeText && responseType != questionResponseTypeMultiple && responseType != questionResponseTypeNumber {
		return errors.New("response type must be text, multiple choice, or number")
	}
	for _, option := range options {
		if len([]rune(option)) > 200 {
			return errors.New("multiple choice options must be 200 characters or fewer")
		}
	}
	switch responseType {
	case questionResponseTypeMultiple:
		if len(options) < 2 {
			return errors.New("multiple choice questions require at least two options")
		}
		if len(options) > 30 {
			return errors.New("multiple choice questions support up to 30 options")
		}
	default:
		if len(options) > 0 {
			return errors.New("response options are only allowed for multiple choice questions")
		}
	}
	return nil
}

func validateCandidateInterviewQuestionAnswer(question candidateInterviewQuestion, answer string) error {
	if answer == "" {
		return errors.New("every interview question must be answered")
	}
	if len([]rune(answer)) > 3000 {
		return errors.New("interview question answers must be 3000 characters or fewer")
	}
	switch normalizeQuestionResponseType(question.ResponseType) {
	case questionResponseTypeNumber:
		if _, err := strconv.ParseFloat(answer, 64); err != nil {
			return fmt.Errorf("question '%s' requires a numeric answer", strings.TrimSpace(question.Question))
		}
	case questionResponseTypeMultiple:
		options := normalizeQuestionResponseOptions(question.ResponseOptions)
		for _, option := range options {
			if answer == option {
				return nil
			}
		}
		return fmt.Errorf("question '%s' requires selecting one of the provided options", strings.TrimSpace(question.Question))
	}
	return nil
}

func parseInterviewScheduledAt(raw string) (time.Time, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return time.Time{}, errors.New("interview date and time are required")
	}
	layouts := []string{
		time.RFC3339,
		"2006-01-02T15:04",
		"2006-01-02 15:04",
	}
	for _, layout := range layouts {
		if layout == time.RFC3339 {
			if parsed, err := time.Parse(layout, trimmed); err == nil {
				return parsed.UTC(), nil
			}
			continue
		}
		if parsed, err := time.ParseInLocation(layout, trimmed, time.Local); err == nil {
			return parsed.UTC(), nil
		}
	}
	return time.Time{}, errors.New("interview date/time is invalid")
}

func valueAsString(value any) (string, error) {
	switch v := value.(type) {
	case string:
		return v, nil
	case float64:
		return strconv.FormatInt(int64(v), 10), nil
	default:
		return "", fmt.Errorf("unexpected type for string: %T", value)
	}
}

func valueAsInt64(value any) (int64, error) {
	switch v := value.(type) {
	case float64:
		return int64(v), nil
	case string:
		return strconv.ParseInt(v, 10, 64)
	default:
		return 0, fmt.Errorf("unexpected type for int64: %T", value)
	}
}

func valueAsFloat64(value any) (float64, error) {
	switch v := value.(type) {
	case float64:
		return v, nil
	case string:
		return strconv.ParseFloat(v, 64)
	default:
		return 0, fmt.Errorf("unexpected type for float64: %T", value)
	}
}

func sqliteStringLiteral(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

type pdfFormExportPayload struct {
	Forms []pdfFormExportEntry `json:"forms"`
}

type pdfFormExportEntry struct {
	Textfield []pdfFormExportTextField `json:"textfield"`
	Checkbox  []pdfFormExportCheckBox  `json:"checkbox"`
	Combobox  []pdfFormExportTextField `json:"combobox"`
}

type pdfFormExportTextField struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type pdfFormExportCheckBox struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Value bool   `json:"value"`
}

func generateFilledI9PDF(values url.Values) ([]byte, error) {
	textFieldMap := map[string]string{
		"last_name":                 "Last Name (Family Name)",
		"first_name":                "First Name Given Name",
		"middle_initial":            "Employee Middle Initial (if any)",
		"other_last_names":          "Employee Other Last Names Used (if any)",
		"address":                   "Address Street Number and Name",
		"apt_number":                "Apt Number (if any)",
		"city":                      "City or Town",
		"state":                     "State",
		"zip_code":                  "ZIP Code",
		"date_of_birth":             "Date of Birth mmddyyyy",
		"ssn":                       "US Social Security Number",
		"email":                     "Employees E-mail Address",
		"phone":                     "Telephone Number",
		"citizenship_lpr_number":    "3 A lawful permanent resident Enter USCIS or ANumber",
		"alien_exp_date":            "Exp Date mmddyyyy",
		"alien_uscis_number":        "USCIS ANumber",
		"alien_i94_number":          "Form I94 Admission Number",
		"alien_passport_country":    "Foreign Passport Number and Country of IssuanceRow1",
		"employee_signature_date":   "Today's Date mmddyyy",
		"list_a_title":              "Document Title 1",
		"list_a_issuing_authority":  "Issuing Authority 1",
		"list_a_number":             "Document Number 0 (if any)",
		"list_a_expiration":         "Expiration Date if any",
		"list_b_title":              "List B Document 1 Title",
		"list_b_issuing_authority":  "List B Issuing Authority 1",
		"list_b_number":             "List B Document Number 1",
		"list_b_expiration":         "List B Expiration Date 1",
		"list_c_title":              "List C Document Title 1",
		"list_c_issuing_authority":  "List C Issuing Authority 1",
		"list_c_number":             "List C Document Number 1",
		"list_c_expiration":         "List C Expiration Date 1",
		"first_day_employed":        "FirstDayEmployed mmddyyyy",
		"employer_name_title":       "Last Name First Name and Title of Employer or Authorized Representative",
		"employer_signature":        "Signature of Employer or AR",
		"employer_signature_date":   "S2 Todays Date mmddyyyy",
		"employer_business_name":    "Employers Business or Org Name",
		"employer_business_address": "Employers Business or Org Address",
		"additional_info":           "Additional Information",
	}
	pdfTextValues := map[string]string{}
	for formKey, pdfFieldName := range textFieldMap {
		raw := strings.TrimSpace(values.Get(formKey))
		if raw == "" {
			continue
		}
		pdfTextValues[pdfFieldName] = raw
	}
	if stateRaw := strings.TrimSpace(values.Get("state")); stateRaw != "" {
		pdfTextValues["State_Real"] = stateRaw
	}

	citizenshipStatus := normalizeI9CitizenshipStatus(values.Get("citizenship_status"))
	if citizenshipStatus == "" {
		return nil, errors.New("citizenship/immigration status is required")
	}
	statusTextFieldMap := map[string]string{
		"citizen":             "CHECK_1",
		"noncitizen_national": "CHECK_2",
		"lpr":                 "CHECK_3",
		"alien_authorized":    "CHECK_4",
	}
	statusCheckboxFieldMap := map[string]string{
		"citizen":             "CB_1",
		"noncitizen_national": "CB_2",
		"lpr":                 "CB_3",
		"alien_authorized":    "CB_4",
	}
	textFieldName, ok := statusTextFieldMap[citizenshipStatus]
	if !ok {
		return nil, errors.New("invalid citizenship/immigration status")
	}
	// Current I-9 template uses text fields CHECK_1..CHECK_4 for status marks.
	pdfTextValues[textFieldName] = "X"

	pdfCheckboxValues := map[string]bool{
		"CB_1": false,
		"CB_2": false,
		"CB_3": false,
		"CB_4": false,
	}
	if checkboxFieldName, ok := statusCheckboxFieldMap[citizenshipStatus]; ok {
		// Backward compatibility for templates that still use checkbox widgets.
		pdfCheckboxValues[checkboxFieldName] = true
	}

	if len(pdfTextValues) == 0 {
		return nil, errors.New("enter at least one i-9 field before saving")
	}
	return fillPDFTemplate("docs/i9.pdf", pdfTextValues, pdfCheckboxValues)
}

func normalizeI9CitizenshipStatus(raw string) string {
	status := strings.ToLower(strings.TrimSpace(raw))
	switch status {
	case "citizen", "u.s. citizen", "us citizen", "a citizen of the united states", "1", "1.", "1. a citizen of the united states":
		return "citizen"
	case "noncitizen_national", "noncitizen national", "a noncitizen national of the united states", "2", "2.", "2. a noncitizen national of the united states", "a noncitizen national of the united states (see instructions.)":
		return "noncitizen_national"
	case "lpr", "lawful permanent resident", "lawful_permanent_resident", "3", "3.", "3. a lawful permanent resident", "a lawful permanent resident (enter uscis or a-number.)":
		return "lpr"
	case "alien_authorized", "alien authorized to work", "authorized_alien", "authorized alien", "4", "4.", "4. an alien authorized to work until":
		return "alien_authorized"
	}
	return ""
}

func generateFilledW4PDF(values url.Values) ([]byte, error) {
	textFieldMap := map[string]string{
		"first_name_middle":  "topmostSubform[0].Page1[0].Step1a[0].f1_01[0]",
		"last_name":          "topmostSubform[0].Page1[0].Step1a[0].f1_02[0]",
		"address":            "topmostSubform[0].Page1[0].Step1a[0].f1_03[0]",
		"city_state_zip":     "topmostSubform[0].Page1[0].Step1a[0].f1_04[0]",
		"ssn":                "topmostSubform[0].Page1[0].f1_05[0]",
		"dependents_under17": "topmostSubform[0].Page1[0].Step3_ReadOrder[0].f1_06[0]",
		"other_dependents":   "topmostSubform[0].Page1[0].f1_10[0]",
		"dependents_total":   "topmostSubform[0].Page1[0].Step3_ReadOrder[0].f1_07[0]",
		"other_income":       "topmostSubform[0].Page1[0].f1_08[0]",
		"deductions":         "topmostSubform[0].Page1[0].f1_09[0]",
		"extra_withholding":  "topmostSubform[0].Page1[0].f1_11[0]",
		"employer_name_addr": "topmostSubform[0].Page1[0].f1_12[0]",
		"employer_date":      "topmostSubform[0].Page1[0].f1_13[0]",
		"employer_ein":       "topmostSubform[0].Page1[0].f1_14[0]",
	}
	pdfTextValues := map[string]string{}
	for formKey, pdfFieldName := range textFieldMap {
		raw := strings.TrimSpace(values.Get(formKey))
		if raw == "" {
			continue
		}
		pdfTextValues[pdfFieldName] = raw
	}
	under17Amount, hasUnder17Amount := parseWholeDollarAmount(values.Get("dependents_under17"))
	otherDependentsAmount, hasOtherDependentsAmount := parseWholeDollarAmount(values.Get("other_dependents"))
	if hasUnder17Amount || hasOtherDependentsAmount {
		dependentsSum := under17Amount + otherDependentsAmount
		dependentsSumText := strconv.FormatInt(dependentsSum, 10)
		// Keep only the W-4 Step 3(c) total field in sync with computed amounts.
		pdfTextValues["topmostSubform[0].Page1[0].Step3_ReadOrder[0].f1_07[0]"] = dependentsSumText
	}
	// Signature line is stamped from drawn signature; avoid typed/text signature in this field.
	delete(pdfTextValues, "Employee Signature")
	employeeDate := strings.TrimSpace(values.Get("employee_signature_date"))
	if employeeDate == "" {
		employeeDate = strings.TrimSpace(values.Get("date"))
	}
	if employeeDate != "" {
		pdfTextValues["Today's Date"] = employeeDate
	}

	pdfCheckboxValues := map[string]bool{
		"topmostSubform[0].Page1[0].c1_1[0]": false,
		"topmostSubform[0].Page1[0].c1_1[1]": false,
		"topmostSubform[0].Page1[0].c1_1[2]": false,
		"topmostSubform[0].Page1[0].c1_2[0]": false,
		"topmostSubform[0].Page1[0].c1_3[0]": false,
	}

	switch strings.ToLower(strings.TrimSpace(values.Get("filing_status"))) {
	case "single":
		pdfCheckboxValues["topmostSubform[0].Page1[0].c1_1[0]"] = true
	case "married":
		pdfCheckboxValues["topmostSubform[0].Page1[0].c1_1[1]"] = true
	case "head":
		pdfCheckboxValues["topmostSubform[0].Page1[0].c1_1[2]"] = true
	}
	if parseBoolQueryValue(values.Get("multiple_jobs")) {
		pdfCheckboxValues["topmostSubform[0].Page1[0].c1_2[0]"] = true
	}
	if parseBoolQueryValue(values.Get("exempt")) {
		pdfCheckboxValues["topmostSubform[0].Page1[0].c1_3[0]"] = true
	}

	if len(pdfTextValues) == 0 &&
		!pdfCheckboxValues["topmostSubform[0].Page1[0].c1_1[0]"] &&
		!pdfCheckboxValues["topmostSubform[0].Page1[0].c1_1[1]"] &&
		!pdfCheckboxValues["topmostSubform[0].Page1[0].c1_1[2]"] &&
		!pdfCheckboxValues["topmostSubform[0].Page1[0].c1_2[0]"] &&
		!pdfCheckboxValues["topmostSubform[0].Page1[0].c1_3[0]"] {
		return nil, errors.New("enter at least one w-4 field before saving")
	}

	return fillPDFTemplate("docs/w4.pdf", pdfTextValues, pdfCheckboxValues)
}

func parseWholeDollarAmount(raw string) (int64, bool) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return 0, false
	}
	sanitized := strings.NewReplacer("$", "", ",", "", " ", "").Replace(trimmed)
	if dot := strings.IndexByte(sanitized, '.'); dot >= 0 {
		sanitized = sanitized[:dot]
	}
	if sanitized == "" {
		return 0, false
	}
	amount, err := strconv.ParseInt(sanitized, 10, 64)
	if err != nil || amount < 0 {
		return 0, false
	}
	return amount, true
}

func normalizeW4DollarFields(values url.Values) error {
	fieldLabels := map[string]string{
		"other_income":      "other income",
		"deductions":        "deductions",
		"extra_withholding": "extra withholding",
	}
	for key, label := range fieldLabels {
		normalized, err := normalizeDollarAmount(values.Get(key))
		if err != nil {
			return fmt.Errorf("%s must be a valid dollar amount (example: 100, 100.00, or $100.00)", label)
		}
		values.Set(key, normalized)
	}
	return nil
}

func normalizeDollarAmount(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", nil
	}
	sanitized := strings.NewReplacer(",", "", "$", "", " ", "").Replace(trimmed)
	if sanitized == "" {
		return "", errors.New("invalid amount")
	}
	if strings.HasPrefix(sanitized, "-") {
		return "", errors.New("amount cannot be negative")
	}
	if !w4CurrencyAmountPattern.MatchString(sanitized) {
		return "", errors.New("invalid amount")
	}
	if dot := strings.IndexByte(sanitized, '.'); dot >= 0 {
		whole := strings.TrimLeft(sanitized[:dot], "0")
		if whole == "" {
			whole = "0"
		}
		fraction := sanitized[dot+1:]
		return whole + "." + fraction, nil
	}
	whole := strings.TrimLeft(sanitized, "0")
	if whole == "" {
		whole = "0"
	}
	return whole, nil
}

func fillPDFTemplate(templatePath string, textValues map[string]string, checkValues map[string]bool) ([]byte, error) {
	if _, err := os.Stat(templatePath); err != nil {
		return nil, errors.New("paperwork template is missing")
	}
	pdfcpuPath, err := resolvePdfcpuPath()
	if err != nil {
		return nil, errors.New("pdfcpu is required on the host to generate paperwork")
	}

	tmpDir, err := os.MkdirTemp("", "cfasuite-pdf-fill-*")
	if err != nil {
		return nil, errors.New("unable to prepare pdf generation")
	}
	defer func() {
		_ = os.RemoveAll(tmpDir)
	}()

	exportPath := filepath.Join(tmpDir, "export.json")
	fillPath := filepath.Join(tmpDir, "fill.json")
	outPath := filepath.Join(tmpDir, "filled.pdf")
	lockedOutPath := filepath.Join(tmpDir, "filled-locked.pdf")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if output, err := exec.CommandContext(ctx, pdfcpuPath, "form", "export", templatePath, exportPath).CombinedOutput(); err != nil {
		return nil, fmt.Errorf("unable to export template fields: %s", strings.TrimSpace(string(output)))
	}

	exportRaw, err := os.ReadFile(exportPath)
	if err != nil {
		return nil, errors.New("unable to read exported template fields")
	}
	var payload pdfFormExportPayload
	if err := json.Unmarshal(exportRaw, &payload); err != nil {
		return nil, errors.New("unable to parse exported template fields")
	}
	if len(payload.Forms) == 0 {
		return nil, errors.New("template does not include fillable form fields")
	}

	for formIdx := range payload.Forms {
		for fieldIdx := range payload.Forms[formIdx].Textfield {
			name := payload.Forms[formIdx].Textfield[fieldIdx].Name
			if value, ok := textValues[name]; ok {
				payload.Forms[formIdx].Textfield[fieldIdx].Value = value
			}
		}
		for fieldIdx := range payload.Forms[formIdx].Combobox {
			name := payload.Forms[formIdx].Combobox[fieldIdx].Name
			if value, ok := textValues[name]; ok {
				payload.Forms[formIdx].Combobox[fieldIdx].Value = value
			}
		}
		for fieldIdx := range payload.Forms[formIdx].Checkbox {
			name := payload.Forms[formIdx].Checkbox[fieldIdx].Name
			id := strings.TrimSpace(payload.Forms[formIdx].Checkbox[fieldIdx].ID)
			if value, ok := checkValues[name]; ok {
				payload.Forms[formIdx].Checkbox[fieldIdx].Value = value
				continue
			}
			if id != "" {
				if value, ok := checkValues[id]; ok {
					payload.Forms[formIdx].Checkbox[fieldIdx].Value = value
				}
			}
		}
	}

	filledRaw, err := json.Marshal(payload)
	if err != nil {
		return nil, errors.New("unable to serialize filled form fields")
	}
	if err := os.WriteFile(fillPath, filledRaw, 0o600); err != nil {
		return nil, errors.New("unable to stage filled form")
	}
	if output, err := exec.CommandContext(ctx, pdfcpuPath, "form", "fill", templatePath, fillPath, outPath).CombinedOutput(); err != nil {
		return nil, fmt.Errorf("unable to fill template: %s", strings.TrimSpace(string(output)))
	}
	// Lock form fields so checkbox/radio appearances render consistently across PDF viewers.
	finalPath := outPath
	if output, err := exec.CommandContext(ctx, pdfcpuPath, "form", "lock", outPath, lockedOutPath).CombinedOutput(); err == nil {
		finalPath = lockedOutPath
	} else {
		log.Printf("warning: unable to lock filled pdf %s: %s", templatePath, strings.TrimSpace(string(output)))
	}

	pdfData, err := os.ReadFile(finalPath)
	if err != nil {
		return nil, errors.New("unable to read generated pdf")
	}
	if len(pdfData) == 0 {
		return nil, errors.New("generated pdf is empty")
	}
	return pdfData, nil
}

func parseUploadedPhoto(r *http.Request) ([]byte, string, error) {
	return parseUploadedPhotoWithField(r, "photo_file")
}

func parseUploadedFileWithField(r *http.Request, fieldName string, maxBytes int64, allowedMimes []string, requiredMessage string) ([]byte, string, string, error) {
	if maxBytes <= 0 {
		maxBytes = 10 << 20
	}
	if err := r.ParseMultipartForm(maxBytes + (2 << 20)); err != nil {
		return nil, "", "", errors.New("invalid upload form")
	}
	file, header, err := r.FormFile(fieldName)
	if err != nil {
		return nil, "", "", errors.New(requiredMessage)
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maxBytes))
	if err != nil {
		return nil, "", "", errors.New("unable to read uploaded file")
	}
	if len(raw) == 0 {
		return nil, "", "", errors.New("uploaded file is empty")
	}
	detected := http.DetectContentType(raw)
	if len(allowedMimes) > 0 {
		ok := false
		for _, allowed := range allowedMimes {
			if strings.EqualFold(strings.TrimSpace(allowed), detected) {
				ok = true
				break
			}
		}
		if !ok {
			return nil, "", "", errors.New("unsupported file type")
		}
	}
	fileName := strings.TrimSpace(header.Filename)
	if fileName == "" {
		ext := filepath.Ext(fieldName)
		if ext == "" {
			ext = ".bin"
		}
		fileName = fieldName + ext
	}
	return raw, detected, fileName, nil
}

func parseOptionalUploadedFileWithField(r *http.Request, fieldName string, maxBytes int64, allowedMimes []string) ([]byte, string, string, bool, error) {
	if maxBytes <= 0 {
		maxBytes = 10 << 20
	}
	contentType := strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Type")))
	if !strings.HasPrefix(contentType, "multipart/form-data") {
		return nil, "", "", false, nil
	}
	file, header, err := r.FormFile(fieldName)
	if err != nil {
		if errors.Is(err, http.ErrMissingFile) || strings.Contains(strings.ToLower(err.Error()), "no such file") {
			return nil, "", "", false, nil
		}
		return nil, "", "", false, errors.New("invalid uploaded file")
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maxBytes))
	if err != nil {
		return nil, "", "", false, errors.New("unable to read uploaded file")
	}
	if len(raw) == 0 {
		return nil, "", "", false, errors.New("uploaded file is empty")
	}
	detected := http.DetectContentType(raw)
	if len(allowedMimes) > 0 {
		ok := false
		for _, allowed := range allowedMimes {
			if strings.EqualFold(strings.TrimSpace(allowed), detected) {
				ok = true
				break
			}
		}
		if !ok {
			return nil, "", "", false, errors.New("unsupported file type")
		}
	}
	fileName := strings.TrimSpace(header.Filename)
	if fileName == "" {
		ext := filepath.Ext(fieldName)
		if ext == "" {
			ext = ".bin"
		}
		fileName = fieldName + ext
	}
	return raw, detected, fileName, true, nil
}

func parseDataURLBinary(value string, allowedMimes []string, maxBytes int) ([]byte, string, error) {
	raw := strings.TrimSpace(value)
	if raw == "" {
		return nil, "", errors.New("empty data url")
	}
	if !strings.HasPrefix(raw, "data:") {
		return nil, "", errors.New("invalid data url prefix")
	}
	comma := strings.Index(raw, ",")
	if comma <= 5 {
		return nil, "", errors.New("invalid data url payload")
	}
	meta := raw[5:comma]
	payload := raw[comma+1:]
	if !strings.HasSuffix(strings.ToLower(meta), ";base64") {
		return nil, "", errors.New("data url must be base64")
	}
	mime := strings.TrimSpace(meta[:len(meta)-len(";base64")])
	if mime == "" {
		return nil, "", errors.New("missing data url mime type")
	}
	if len(allowedMimes) > 0 {
		ok := false
		for _, allowed := range allowedMimes {
			if strings.EqualFold(strings.TrimSpace(allowed), mime) {
				ok = true
				break
			}
		}
		if !ok {
			return nil, "", errors.New("unsupported data url mime type")
		}
	}
	decoded, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return nil, "", errors.New("unable to decode data url")
	}
	if len(decoded) == 0 {
		return nil, "", errors.New("empty data url content")
	}
	if maxBytes > 0 && len(decoded) > maxBytes {
		return nil, "", errors.New("data url exceeds max size")
	}
	detected := http.DetectContentType(decoded)
	if !strings.EqualFold(detected, mime) {
		return nil, "", errors.New("data url mime does not match content")
	}
	return decoded, detected, nil
}

func parseUploadedPhotoWithField(r *http.Request, fieldName string) ([]byte, string, error) {
	if err := r.ParseMultipartForm(12 << 20); err != nil {
		return nil, "", errors.New("invalid upload form")
	}
	file, _, err := r.FormFile(fieldName)
	if err != nil {
		return nil, "", errors.New("photo file is required")
	}
	defer file.Close()

	raw, err := io.ReadAll(io.LimitReader(file, 10<<20))
	if err != nil {
		return nil, "", errors.New("unable to read photo file")
	}
	if len(raw) == 0 {
		return nil, "", errors.New("photo file is empty")
	}

	cropX := parsePositiveInt(r.FormValue("crop_x"), 0)
	cropY := parsePositiveInt(r.FormValue("crop_y"), 0)
	cropSize := parsePositiveInt(r.FormValue("crop_size"), 0)
	return processUploadedPhotoBytes(raw, cropX, cropY, cropSize)
}

func processUploadedPhotoBytes(raw []byte, cropX, cropY, cropSize int) ([]byte, string, error) {
	mime := http.DetectContentType(raw)
	switch mime {
	case "image/png", "image/jpeg", "image/webp":
	default:
		return nil, "", errors.New("photo must be png, jpeg, or webp")
	}

	img, _, err := image.Decode(bytes.NewReader(raw))
	if err != nil {
		if decoded, decodeErr := webp.Decode(bytes.NewReader(raw)); decodeErr == nil {
			img = decoded
		} else {
			return nil, "", errors.New("unable to decode photo")
		}
	}

	bounds := img.Bounds()
	width := bounds.Dx()
	height := bounds.Dy()
	if width <= 0 || height <= 0 {
		return nil, "", errors.New("invalid image dimensions")
	}

	minDim := width
	if height < minDim {
		minDim = height
	}
	if cropSize <= 0 || cropSize > minDim {
		cropSize = minDim
		cropX = (width - cropSize) / 2
		cropY = (height - cropSize) / 2
	}
	if cropX < 0 {
		cropX = 0
	}
	if cropY < 0 {
		cropY = 0
	}
	if cropX+cropSize > width {
		cropX = width - cropSize
	}
	if cropY+cropSize > height {
		cropY = height - cropSize
	}

	cropRect := image.Rect(0, 0, cropSize, cropSize)
	dst := image.NewRGBA(cropRect)
	srcPoint := image.Point{X: bounds.Min.X + cropX, Y: bounds.Min.Y + cropY}
	stddraw.Draw(dst, cropRect, img, srcPoint, stddraw.Src)

	// Keep uploads lightweight and predictable for rendering.
	targetSize := 512
	resized := image.NewRGBA(image.Rect(0, 0, targetSize, targetSize))
	xdraw.CatmullRom.Scale(resized, resized.Bounds(), dst, dst.Bounds(), xdraw.Over, nil)

	optimized, err := encodeCompactWebP(resized)
	if err != nil {
		// Fallback to PNG if cwebp is unavailable in this runtime.
		var out bytes.Buffer
		if pngErr := png.Encode(&out, resized); pngErr != nil {
			return nil, "", errors.New("unable to encode optimized image")
		}
		return out.Bytes(), "image/png", nil
	}
	return optimized, "image/webp", nil
}

func encodeCompactWebP(img image.Image) ([]byte, error) {
	tmpIn, err := os.CreateTemp("", "cfasuite-upload-*.png")
	if err != nil {
		return nil, err
	}
	_ = tmpIn.Close()
	tmpOut := tmpIn.Name() + ".webp"
	defer func() {
		_ = os.Remove(tmpIn.Name())
		_ = os.Remove(tmpOut)
	}()

	inFile, err := os.Create(tmpIn.Name())
	if err != nil {
		return nil, err
	}
	if err := png.Encode(inFile, img); err != nil {
		_ = inFile.Close()
		return nil, err
	}
	_ = inFile.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "cwebp", "-quiet", "-q", "78", "-m", "6", "-af", tmpIn.Name(), "-o", tmpOut)
	if output, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("cwebp failed: %w (%s)", err, strings.TrimSpace(string(output)))
	}
	webpBytes, err := os.ReadFile(tmpOut)
	if err != nil {
		return nil, err
	}
	if len(webpBytes) == 0 {
		return nil, errors.New("empty webp output")
	}
	return webpBytes, nil
}

func expireSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
	})
}

func envOrDefault(name, fallback string) string {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	return value
}

func parseBoolQueryValue(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "true", "yes", "y", "on":
		return true
	default:
		return false
	}
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
