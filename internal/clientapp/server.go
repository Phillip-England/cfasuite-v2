package clientapp

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"math"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/phillip-england/cfasuite/internal/middleware"
	"github.com/xuri/excelize/v2"
)

const (
	csrfHeaderName          = "X-CSRF-Token"
	apiSessionCookie        = "cfasuite_session"
	adminSessionCookie      = "cfasuite_session_admin"
	restaurantSessionCookie = "cfasuite_session_restaurant"
	teamSessionCookie       = "cfasuite_session_team"
	uniformSystemKeyShoes   = "shoes"
)

var interviewQuestionStarterCatalog = []interviewQuestionStarter{
	{
		Key:          "why_chickfila",
		Question:     "Why do you want to work at Chick-fil-A?",
		ResponseType: "text",
	},
	{
		Key:          "hospitality_meaning",
		Question:     "What does great hospitality mean to you?",
		ResponseType: "text",
	},
	{
		Key:          "teamwork_example",
		Question:     "Tell me about a time you helped a teammate succeed.",
		ResponseType: "text",
	},
	{
		Key:          "guest_recovery",
		Question:     "Describe a time you helped a frustrated guest or customer.",
		ResponseType: "text",
	},
	{
		Key:          "fast_paced",
		Question:     "How do you stay accurate and positive during a fast-paced rush?",
		ResponseType: "text",
	},
	{
		Key:          "feedback_application",
		Question:     "Tell me about feedback you received and how you applied it.",
		ResponseType: "text",
	},
	{
		Key:          "dependable_team",
		Question:     "What does being dependable look like on a team?",
		ResponseType: "text",
	},
	{
		Key:          "weekend_availability",
		Question:     "Are you available to work weekends?",
		ResponseType: "yes_no",
	},
	{
		Key:          "open_close_availability",
		Question:     "Are you available to open or close when needed?",
		ResponseType: "yes_no",
	},
	{
		Key:          "food_safety_importance",
		Question:     "Why is food safety important in a restaurant environment?",
		ResponseType: "text",
	},
}

type Config struct {
	Addr         string
	APIBaseURL   string
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
}

type pageData struct {
	Error                 string
	CSRF                  string
	Page                  int
	Token                 string
	Search                string
	ReturnPath            string
	ResolvedTimePunchName string
	ResolvedEmployeeName  string

	Locations  []locationView
	HasPrev    bool
	HasNext    bool
	PrevPage   int
	NextPage   int
	TotalCount int

	Location                           *locationView
	Employee                           *employeeView
	BusinessDay                        *businessDayView
	Employees                          []employeeView
	ActiveEmployees                    []employeeView
	NewHireEmployees                   []employeeView
	BusinessDays                       []businessDayView
	ArchivedEmployees                  []employeeView
	TimePunchEntries                   []timePunchEntryView
	ArchivedTimePunchEntries           []timePunchEntryView
	TimeOffRequests                    []timeOffRequestView
	ArchivedTimeOffRequests            []timeOffRequestView
	UniformItems                       []uniformItemView
	UniformOrders                      []uniformOrderView
	ArchivedOrders                     []uniformOrderView
	UniformItem                        *uniformItemView
	Candidates                         []candidateView
	ArchivedCandidates                 []candidateView
	EmployeeScorecards                 []candidateView
	CandidateValues                    []candidateValueView
	InterviewNames                     []candidateInterviewNameView
	InterviewQuestions                 []candidateInterviewQuestionView
	InterviewQuestionStarters          []interviewQuestionStarterView
	InterviewLinks                     []candidateInterviewLinkView
	InterviewCalendar                  []interviewCalendarEntryView
	Candidate                          *candidateView
	Interview                          *candidateInterviewView
	InterviewLink                      *candidateInterviewLinkView
	EmployeeNames                      []string
	Departments                        []string
	LocationDepartments                []departmentView
	LocationJobs                       []jobView
	EmployeeAdditionalCompensations    []employeeAdditionalCompView
	DepartmentsMissingJobs             []string
	HasOpenTimePunchEntries            bool
	HasIncompleteBusinessDays          bool
	HasOverdueTimeOffRequests          bool
	OverdueTimeOffRequestCount         int
	HasUpcomingTimeOffRequests         bool
	UpcomingTimeOffRequestCount        int
	HasPendingUniformOrders            bool
	PendingUniformOrderCount           int
	HasOutstandingUniformCharges       bool
	OutstandingUniformChargeOrderCount int
	HasStaleCandidateInterviews        bool
	StaleCandidateInterviewCount       int
	HasActiveCandidates                bool
	ActiveCandidateCount               int
	HasInterviewTypes                  bool
	InterviewTypesMissingQuestions     []string
	SuccessMessage                     string
	UploadLink                         string
	EmployeePaperworkLink              string
	LocationSettings                   *locationSettingsView
	TimePunchLink                      string
	TimeOffLink                        string
	UniformLink                        string
	TeamLoginLink                      string
	EmployeeI9                         *employeeI9View
	EmployeeI9Documents                []employeeI9DocumentView
	EmployeeI9History                  []paperworkHistoryView
	EmployeeW4                         *employeeI9View
	EmployeeW4History                  []paperworkHistoryView
	PaperworkSections                  []paperworkSectionView
	CanManualPaperworkUpload           bool
	ManualPaperworkUploadMissing       []string
	EmployeesMissingProfile            []employeeProfileCompletenessView
	HasEmployeesMissingProfile         bool
	EmployeesMissingProfileCount       int
	EmployeeMissingProfileFields       []string
	EmployeeMissingProfileFieldSet     map[string]bool
	HasEmployeeMissingProfileFields    bool
	IsArchivedEmployee                 bool
	IsNewHireEmployee                  bool
	IsActiveEmployee                   bool
	CurrentUser                        *authSessionView
	EmployeePayAmountInput             string
	EmployeeBirthMonthInput            string
	EmployeeBirthDayInput              string
	EmployeeBirthYearInput             string
	TeamDocuments                      []teamDocumentView
}

type locationView struct {
	Name      string `json:"name"`
	Number    string `json:"number"`
	Email     string `json:"email"`
	Phone     string `json:"phone"`
	CreatedAt string `json:"createdAt"`
}

type employeeView struct {
	FirstName             string `json:"firstName"`
	LastName              string `json:"lastName"`
	TimePunchName         string `json:"timePunchName"`
	EmployeeNumber        string `json:"employeeNumber"`
	Department            string `json:"department"`
	DepartmentID          int64  `json:"departmentId"`
	JobID                 int64  `json:"jobId"`
	JobName               string `json:"jobName"`
	PayBandID             int64  `json:"payBandId"`
	PayBandName           string `json:"payBandName"`
	PayType               string `json:"payType"`
	PayAmountCents        int64  `json:"payAmountCents"`
	AdditionalCompCents   int64  `json:"additionalCompCents"`
	EffectivePayCents     int64  `json:"effectivePayCents"`
	Birthday              string `json:"birthday"`
	Email                 string `json:"email"`
	Phone                 string `json:"phone"`
	Address               string `json:"address"`
	AptNumber             string `json:"aptNumber"`
	City                  string `json:"city"`
	State                 string `json:"state"`
	ZipCode               string `json:"zipCode"`
	HasPhoto              bool   `json:"hasPhoto"`
	HasClockInPIN         bool   `json:"hasClockInPin"`
	HasCompletedPaperwork bool   `json:"hasCompletedPaperwork"`
	ArchivedAt            string `json:"archivedAt"`
}

type departmentView struct {
	ID             int64  `json:"id"`
	LocationNumber string `json:"locationNumber"`
	Name           string `json:"name"`
	CreatedAt      string `json:"createdAt"`
}

type jobView struct {
	ID              int64    `json:"id"`
	LocationNumber  string   `json:"locationNumber"`
	DepartmentID    int64    `json:"departmentId"`
	DepartmentName  string   `json:"departmentName"`
	DepartmentIDs   []int64  `json:"departmentIds"`
	DepartmentNames []string `json:"departmentNames"`
	Name            string   `json:"name"`
	PayType         string   `json:"payType"`
	PayAmountCents  int64    `json:"payAmountCents"`
	PayAmountDisplay string  `json:"-"`
	CreatedAt       string   `json:"createdAt"`
}

type employeeAdditionalCompView struct {
	ID             int64  `json:"id"`
	LocationNumber string `json:"locationNumber"`
	TimePunchName  string `json:"timePunchName"`
	Label          string `json:"label"`
	AmountCents    int64  `json:"amountCents"`
	CreatedAt      string `json:"createdAt"`
}

type employeeI9View struct {
	LocationNumber string `json:"locationNumber"`
	TimePunchName  string `json:"timePunchName"`
	FileName       string `json:"fileName"`
	FileMime       string `json:"fileMime"`
	UpdatedAt      string `json:"updatedAt"`
	CreatedAt      string `json:"createdAt"`
	HasFile        bool   `json:"hasFile"`
}

type employeeI9DocumentView struct {
	ID             int64  `json:"id"`
	LocationNumber string `json:"locationNumber"`
	TimePunchName  string `json:"timePunchName"`
	ListType       string `json:"listType"`
	FileName       string `json:"fileName"`
	FileMime       string `json:"fileMime"`
	CreatedAt      string `json:"createdAt"`
}

type employeeProfileCompletenessView struct {
	Employee      employeeView `json:"employee"`
	MissingFields []string     `json:"missingFields"`
}

type locationsListResponse struct {
	Count      int            `json:"count"`
	Page       int            `json:"page"`
	PerPage    int            `json:"perPage"`
	TotalPages int            `json:"totalPages"`
	Locations  []locationView `json:"locations"`
}

type locationDetailResponse struct {
	Location      locationView `json:"location"`
	EmployeeCount int          `json:"employeeCount"`
}

type locationEmployeesResponse struct {
	Count     int            `json:"count"`
	Employees []employeeView `json:"employees"`
}

type locationDepartmentsResponse struct {
	Count       int              `json:"count"`
	Departments []departmentView `json:"departments"`
}

type locationJobsResponse struct {
	Count int       `json:"count"`
	Jobs  []jobView `json:"jobs"`
}

type employeeAdditionalCompensationsResponse struct {
	Count         int                          `json:"count"`
	TotalCents    int64                        `json:"totalCents"`
	Compensations []employeeAdditionalCompView `json:"compensations"`
}

type employeeDetailResponse struct {
	Employee employeeView `json:"employee"`
}

type employeeI9DetailResponse struct {
	I9        employeeI9View           `json:"i9"`
	Documents []employeeI9DocumentView `json:"documents"`
}

type employeePaperworkResponse struct {
	Paperwork employeeI9View           `json:"paperwork"`
	Documents []employeeI9DocumentView `json:"documents"`
	History   []paperworkHistoryView   `json:"history"`
}

type paperworkHistoryView struct {
	ID        int64  `json:"id"`
	FileName  string `json:"fileName"`
	FileMime  string `json:"fileMime"`
	CreatedAt string `json:"createdAt"`
}

type paperworkSectionView struct {
	Type         string
	Label        string
	HasDocuments bool
	Form         *employeeI9View
	Documents    []employeeI9DocumentView
}

type teamDocumentView struct {
	Label        string
	Category     string
	CreatedAt    string
	DownloadPath string
}

type photoLinkResponse struct {
	Token     string `json:"token"`
	ExpiresAt string `json:"expiresAt"`
}

type publicPhotoTokenResponse struct {
	LocationNumber string `json:"locationNumber"`
	TimePunchName  string `json:"timePunchName"`
	ExpiresAt      string `json:"expiresAt"`
}

type publicPaperworkTokenResponse struct {
	LocationNumber string `json:"locationNumber"`
	LocationName   string `json:"locationName"`
	TimePunchName  string `json:"timePunchName"`
	FirstName      string `json:"firstName"`
	LastName       string `json:"lastName"`
	ExpiresAt      string `json:"expiresAt"`
}

type publicPaperworkSubmitResponse struct {
	Message        string `json:"message"`
	AllSubmitted   bool   `json:"allSubmitted"`
	LocationNumber string `json:"locationNumber"`
	TimePunchName  string `json:"timePunchName"`
}

type publicInterviewResponse struct {
	LocationNumber           string                           `json:"locationNumber"`
	LocationName             string                           `json:"locationName"`
	CandidateID              int64                            `json:"candidateId"`
	CandidateFirstName       string                           `json:"candidateFirstName"`
	CandidateLastName        string                           `json:"candidateLastName"`
	InterviewerTimePunchName string                           `json:"interviewerTimePunchName"`
	InterviewType            string                           `json:"interviewType"`
	ExpiresAt                string                           `json:"expiresAt"`
	Values                   []candidateValueView             `json:"values"`
	Questions                []candidateInterviewQuestionView `json:"questions"`
}

type interviewLinkResponse struct {
	Token     string `json:"token"`
	ExpiresAt string `json:"expiresAt"`
}

type authTokenResponse struct {
	CSRFToken string `json:"csrfToken"`
}

type authSessionView struct {
	ID             int64  `json:"id"`
	Username       string `json:"username"`
	IsAdmin        bool   `json:"isAdmin"`
	Role           string `json:"role"`
	LocationNumber string `json:"locationNumber"`
	TimePunchName  string `json:"timePunchName"`
}

type timePunchEntryView struct {
	ID                       int64  `json:"id"`
	TimePunchName            string `json:"timePunchName"`
	PunchDate                string `json:"punchDate"`
	TimeIn                   string `json:"timeIn"`
	TimeOut                  string `json:"timeOut"`
	Note                     string `json:"note"`
	ForgotBreakClockInReturn bool   `json:"forgotBreakClockInReturn"`
	ArchivedAt               string `json:"archivedAt"`
	CreatedAt                string `json:"createdAt"`
}

type timePunchEntriesResponse struct {
	Count   int                  `json:"count"`
	Entries []timePunchEntryView `json:"entries"`
}

type timePunchLinkResponse struct {
	Token string `json:"token"`
}

type timeOffRequestView struct {
	ID            int64  `json:"id"`
	TimePunchName string `json:"timePunchName"`
	StartDate     string `json:"startDate"`
	EndDate       string `json:"endDate"`
	CreatedAt     string `json:"createdAt"`
	ArchivedAt    string `json:"archivedAt"`
}

type timeOffRequestsResponse struct {
	Count    int                  `json:"count"`
	Requests []timeOffRequestView `json:"requests"`
}

type publicTimePunchResponse struct {
	LocationNumber string         `json:"locationNumber"`
	LocationName   string         `json:"locationName"`
	Employees      []employeeView `json:"employees"`
}

type publicTimeOffResponse struct {
	LocationNumber string         `json:"locationNumber"`
	LocationName   string         `json:"locationName"`
	Employees      []employeeView `json:"employees"`
}

type businessDayView struct {
	ID           int64   `json:"id"`
	BusinessDate string  `json:"businessDate"`
	TotalSales   float64 `json:"totalSales"`
	LaborHours   float64 `json:"laborHours"`
	CreatedAt    string  `json:"createdAt"`
}

type businessDaysResponse struct {
	Count        int               `json:"count"`
	BusinessDays []businessDayView `json:"businessDays"`
}

type businessDayResponse struct {
	BusinessDay businessDayView `json:"businessDay"`
}

type uniformItemView struct {
	ID         int64                  `json:"id"`
	Name       string                 `json:"name"`
	Price      float64                `json:"price"`
	Enabled    bool                   `json:"enabled"`
	SystemKey  string                 `json:"systemKey"`
	ImageData  string                 `json:"imageData"`
	ImageMime  string                 `json:"imageMime"`
	Images     []uniformImageView     `json:"images"`
	Sizes      []string               `json:"sizes"`
	SizeFields []uniformSizeFieldView `json:"sizeFields"`
}

type uniformSizeFieldView struct {
	Label   string   `json:"label"`
	Options []string `json:"options"`
}

type uniformImageView struct {
	ID        int64  `json:"id"`
	ItemID    int64  `json:"itemId"`
	ImageData string `json:"imageData"`
	ImageMime string `json:"imageMime"`
	SortOrder int64  `json:"sortOrder"`
}

type uniformItemsResponse struct {
	Count int               `json:"count"`
	Items []uniformItemView `json:"items"`
}

type uniformOrderView struct {
	ID            int64                  `json:"id"`
	TimePunchName string                 `json:"timePunchName"`
	ItemsSummary  string                 `json:"itemsSummary"`
	Lines         []uniformOrderLineView `json:"lines"`
	Status        string                 `json:"status"`
	Total         float64                `json:"total"`
	CreatedAt     string                 `json:"createdAt"`
	ArchivedAt    string                 `json:"archivedAt"`
}

type uniformOrderLineView struct {
	ID          int64   `json:"id"`
	OrderID     int64   `json:"orderId"`
	ItemID      int64   `json:"itemId"`
	ItemName    string  `json:"itemName"`
	ItemNumber  string  `json:"itemNumber"`
	SizeOption  string  `json:"sizeOption"`
	ExternalURL string  `json:"externalUrl"`
	Note        string  `json:"note"`
	Quantity    int64   `json:"quantity"`
	UnitPrice   float64 `json:"unitPrice"`
	LineTotal   float64 `json:"lineTotal"`
	Purchased   bool    `json:"purchased"`
	PurchasedAt string  `json:"purchasedAt"`
	ChargedBack float64 `json:"chargedBack"`
	Remaining   float64 `json:"remaining"`
}

type uniformOrdersResponse struct {
	Count  int                `json:"count"`
	Orders []uniformOrderView `json:"orders"`
}

type uniformItemDetailResponse struct {
	Item uniformItemView `json:"item"`
}

type uniformLinkResponse struct {
	Token string `json:"token"`
}

type locationSettingsView struct {
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

type locationSettingsResponse struct {
	Settings locationSettingsView `json:"settings"`
}

type candidateValueView struct {
	ID             int64  `json:"id"`
	LocationNumber string `json:"locationNumber"`
	Name           string `json:"name"`
	Description    string `json:"description"`
	CreatedAt      string `json:"createdAt"`
	UpdatedAt      string `json:"updatedAt"`
}

type candidateInterviewGradeView struct {
	ID          int64   `json:"id"`
	InterviewID int64   `json:"interviewId"`
	ValueID     int64   `json:"valueId"`
	ValueName   string  `json:"valueName"`
	LetterGrade string  `json:"letterGrade"`
	Comment     string  `json:"comment"`
	Score       float64 `json:"score"`
}

type candidateInterviewView struct {
	ID                       int64                                  `json:"id"`
	CandidateID              int64                                  `json:"candidateId"`
	LocationNumber           string                                 `json:"locationNumber"`
	InterviewerTimePunchName string                                 `json:"interviewerTimePunchName"`
	InterviewType            string                                 `json:"interviewType"`
	Notes                    string                                 `json:"notes"`
	CreatedAt                string                                 `json:"createdAt"`
	Grades                   []candidateInterviewGradeView          `json:"grades"`
	QuestionAnswers          []candidateInterviewQuestionAnswerView `json:"questionAnswers"`
}

type candidateInterviewNameView struct {
	ID             int64  `json:"id"`
	LocationNumber string `json:"locationNumber"`
	Name           string `json:"name"`
	Priority       int64  `json:"priority"`
	CreatedAt      string `json:"createdAt"`
	UpdatedAt      string `json:"updatedAt"`
}

type candidateInterviewQuestionView struct {
	ID                  int64    `json:"id"`
	LocationNumber      string   `json:"locationNumber"`
	InterviewNameID     int64    `json:"interviewNameId"`
	InterviewName       string   `json:"interviewName"`
	InterviewNameIDs    []int64  `json:"interviewNameIds"`
	InterviewNames      []string `json:"interviewNames"`
	Question            string   `json:"question"`
	ResponseType        string   `json:"responseType"`
	ResponseKind        string   `json:"-"`
	ResponseOptions     []string `json:"responseOptions"`
	ResponseOptionsText string   `json:"-"`
	CreatedAt           string   `json:"createdAt"`
	UpdatedAt           string   `json:"updatedAt"`
}

type interviewQuestionStarter struct {
	Key             string
	Question        string
	ResponseType    string
	ResponseOptions []string
}

type interviewQuestionStarterView struct {
	Key           string
	Question      string
	ResponseLabel string
}

type candidateInterviewLinkView struct {
	Token                    string `json:"token"`
	LocationNumber           string `json:"locationNumber"`
	CandidateID              int64  `json:"candidateId"`
	InterviewerTimePunchName string `json:"interviewerTimePunchName"`
	InterviewType            string `json:"interviewType"`
	ScheduledAt              string `json:"scheduledAt"`
	Link                     string `json:"link"`
	ExpiresAt                string `json:"expiresAt"`
	UsedAt                   string `json:"usedAt"`
	CreatedAt                string `json:"createdAt"`
}

type interviewCalendarEntryView struct {
	Token                    string `json:"token"`
	LocationNumber           string `json:"locationNumber"`
	CandidateID              int64  `json:"candidateId"`
	CandidateFirstName       string `json:"candidateFirstName"`
	CandidateLastName        string `json:"candidateLastName"`
	InterviewerTimePunchName string `json:"interviewerTimePunchName"`
	InterviewType            string `json:"interviewType"`
	ScheduledAt              string `json:"scheduledAt"`
	UsedAt                   string `json:"usedAt"`
	CreatedAt                string `json:"createdAt"`
}

type candidateInterviewQuestionAnswerView struct {
	ID           int64  `json:"id"`
	InterviewID  int64  `json:"interviewId"`
	QuestionID   int64  `json:"questionId"`
	QuestionText string `json:"questionText"`
	Answer       string `json:"answer"`
}

type candidateView struct {
	ID                 int64                    `json:"id"`
	LocationNumber     string                   `json:"locationNumber"`
	FirstName          string                   `json:"firstName"`
	LastName           string                   `json:"lastName"`
	Phone              string                   `json:"phone"`
	Status             string                   `json:"status"`
	HiredTimePunchName string                   `json:"hiredTimePunchName"`
	CreatedAt          string                   `json:"createdAt"`
	UpdatedAt          string                   `json:"updatedAt"`
	ArchivedAt         string                   `json:"archivedAt"`
	Interviews         []candidateInterviewView `json:"interviews"`
}

type candidateValuesResponse struct {
	Count  int                  `json:"count"`
	Values []candidateValueView `json:"values"`
}

type candidateInterviewNamesResponse struct {
	Count int                          `json:"count"`
	Names []candidateInterviewNameView `json:"names"`
}

type candidateInterviewQuestionsResponse struct {
	Count     int                              `json:"count"`
	Questions []candidateInterviewQuestionView `json:"questions"`
}

type candidateInterviewLinksResponse struct {
	Count int                          `json:"count"`
	Links []candidateInterviewLinkView `json:"links"`
}

type interviewCalendarResponse struct {
	Count    int                          `json:"count"`
	Calendar []interviewCalendarEntryView `json:"calendar"`
}

type candidateInterviewLinkResponse struct {
	Link candidateInterviewLinkView `json:"link"`
}

type candidatesResponse struct {
	Count      int             `json:"count"`
	Candidates []candidateView `json:"candidates"`
}

type candidateDetailResponse struct {
	Candidate candidateView `json:"candidate"`
}

type publicUniformOrderResponse struct {
	LocationNumber string            `json:"locationNumber"`
	LocationName   string            `json:"locationName"`
	Employees      []employeeView    `json:"employees"`
	Items          []uniformItemView `json:"items"`
}

type updateBusinessDayRequest struct {
	TotalSales string `json:"totalSales"`
	LaborHours string `json:"laborHours"`
}

//go:embed templates/admin.html templates/login.html templates/team_login.html templates/team_portal.html templates/location_apps.html templates/location.html templates/location_settings.html templates/departments.html templates/archived_employees.html templates/time_punch.html templates/time_off.html templates/business_days.html templates/business_day.html templates/employee.html templates/uniforms.html templates/uniform_orders_archived.html templates/uniform_item.html templates/candidates.html templates/interview_process.html templates/candidate_detail.html templates/candidate_interview.html templates/candidate_interview_link.html templates/candidate_scorecard.html templates/public_photo_upload.html templates/public_employee_paperwork.html templates/public_candidate_interview.html templates/public_time_punch.html templates/public_time_off.html templates/public_uniform_order.html templates/public_uniform_order_item.html assets/app.css assets/upload-drop.js assets/shoe.svg
var templatesFS embed.FS

type server struct {
	apiBaseURL                 string
	apiClient                  *http.Client
	adminTmpl                  *template.Template
	loginTmpl                  *template.Template
	teamLoginTmpl              *template.Template
	teamPortalTmpl             *template.Template
	locationAppsTmpl           *template.Template
	locationTmpl               *template.Template
	locationSettingsTmpl       *template.Template
	departmentsTmpl            *template.Template
	archivedEmployeesTmpl      *template.Template
	timePunchTmpl              *template.Template
	timeOffTmpl                *template.Template
	businessDaysTmpl           *template.Template
	businessDayTmpl            *template.Template
	employeeTmpl               *template.Template
	uniformsTmpl               *template.Template
	uniformArchivedTmpl        *template.Template
	uniformItemTmpl            *template.Template
	candidatesTmpl             *template.Template
	interviewProcessTmpl       *template.Template
	candidateDetailTmpl        *template.Template
	candidateInterviewTmpl     *template.Template
	candidateInterviewLinkTmpl *template.Template
	candidateScorecardTmpl     *template.Template
	publicUploadTmpl           *template.Template
	publicPaperworkTmpl        *template.Template
	publicInterviewTmpl        *template.Template
	publicTimePunchTmpl        *template.Template
	publicTimeOffTmpl          *template.Template
	publicUniformTmpl          *template.Template
	publicUniformItemTmpl      *template.Template
}

func DefaultConfigFromEnv() Config {
	return Config{
		Addr:         envOrDefault("CLIENT_ADDR", ":3000"),
		APIBaseURL:   envOrDefault("API_BASE_URL", "http://localhost:8080"),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
}

func Run(ctx context.Context, cfg Config) error {
	apiClient := &http.Client{Timeout: 8 * time.Second}

	s := &server{
		apiBaseURL:                 strings.TrimRight(cfg.APIBaseURL, "/"),
		apiClient:                  apiClient,
		adminTmpl:                  template.Must(template.ParseFS(templatesFS, "templates/admin.html")),
		loginTmpl:                  template.Must(template.ParseFS(templatesFS, "templates/login.html")),
		teamLoginTmpl:              template.Must(template.ParseFS(templatesFS, "templates/team_login.html")),
		teamPortalTmpl:             template.Must(template.ParseFS(templatesFS, "templates/team_portal.html")),
		locationAppsTmpl:           template.Must(template.ParseFS(templatesFS, "templates/location_apps.html")),
		locationTmpl:               template.Must(template.ParseFS(templatesFS, "templates/location.html")),
		locationSettingsTmpl:       template.Must(template.ParseFS(templatesFS, "templates/location_settings.html")),
		departmentsTmpl:            template.Must(template.ParseFS(templatesFS, "templates/departments.html")),
		archivedEmployeesTmpl:      template.Must(template.ParseFS(templatesFS, "templates/archived_employees.html")),
		timePunchTmpl:              template.Must(template.ParseFS(templatesFS, "templates/time_punch.html")),
		timeOffTmpl:                template.Must(template.ParseFS(templatesFS, "templates/time_off.html")),
		businessDaysTmpl:           template.Must(template.ParseFS(templatesFS, "templates/business_days.html")),
		businessDayTmpl:            template.Must(template.ParseFS(templatesFS, "templates/business_day.html")),
		employeeTmpl:               template.Must(template.ParseFS(templatesFS, "templates/employee.html")),
		uniformsTmpl:               template.Must(template.ParseFS(templatesFS, "templates/uniforms.html")),
		uniformArchivedTmpl:        template.Must(template.ParseFS(templatesFS, "templates/uniform_orders_archived.html")),
		uniformItemTmpl:            template.Must(template.ParseFS(templatesFS, "templates/uniform_item.html")),
		candidatesTmpl:             template.Must(template.ParseFS(templatesFS, "templates/candidates.html")),
		interviewProcessTmpl:       template.Must(template.ParseFS(templatesFS, "templates/interview_process.html")),
		candidateDetailTmpl:        template.Must(template.ParseFS(templatesFS, "templates/candidate_detail.html")),
		candidateInterviewTmpl:     template.Must(template.ParseFS(templatesFS, "templates/candidate_interview.html")),
		candidateInterviewLinkTmpl: template.Must(template.ParseFS(templatesFS, "templates/candidate_interview_link.html")),
		candidateScorecardTmpl:     template.Must(template.ParseFS(templatesFS, "templates/candidate_scorecard.html")),
		publicUploadTmpl:           template.Must(template.ParseFS(templatesFS, "templates/public_photo_upload.html")),
		publicPaperworkTmpl:        template.Must(template.ParseFS(templatesFS, "templates/public_employee_paperwork.html")),
		publicInterviewTmpl:        template.Must(template.ParseFS(templatesFS, "templates/public_candidate_interview.html")),
		publicTimePunchTmpl:        template.Must(template.ParseFS(templatesFS, "templates/public_time_punch.html")),
		publicTimeOffTmpl:          template.Must(template.ParseFS(templatesFS, "templates/public_time_off.html")),
		publicUniformTmpl:          template.Must(template.ParseFS(templatesFS, "templates/public_uniform_order.html")),
		publicUniformItemTmpl:      template.Must(template.ParseFS(templatesFS, "templates/public_uniform_order_item.html")),
	}

	mux := http.NewServeMux()
	mux.Handle("/", http.HandlerFunc(s.loginRoute))
	mux.Handle("/login", http.HandlerFunc(s.loginRoute))
	mux.Handle("/logout", http.HandlerFunc(s.logoutRoute))
	mux.Handle("/team-login", http.HandlerFunc(s.teamLoginRoute))
	mux.Handle("/team-login/", http.HandlerFunc(s.teamLoginTokenRoute))
	mux.Handle("/amin", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/admin", http.StatusFound)
	}))
	mux.Handle("/admin", middleware.Chain(http.HandlerFunc(s.adminPage), s.requireMasterAdmin))
	mux.Handle("/team", middleware.Chain(http.HandlerFunc(s.teamPortalPage), s.requireTeam))
	mux.Handle("/team/", middleware.Chain(http.HandlerFunc(s.teamRoutes), s.requireTeam))
	mux.Handle("/admin/locations", middleware.Chain(http.HandlerFunc(s.createLocationProxy), s.requireMasterAdmin))
	mux.Handle("/admin/locations/", middleware.Chain(http.HandlerFunc(s.locationRoutes), s.requireLocationPortal))
	mux.Handle("/assets/app.css", http.HandlerFunc(s.appCSSFile))
	mux.Handle("/assets/upload-drop.js", http.HandlerFunc(s.uploadDropFile))
	mux.Handle("/assets/shoe.svg", http.HandlerFunc(s.shoeIconFile))
	mux.Handle("/assets/i9-template.pdf", middleware.Chain(http.HandlerFunc(s.i9TemplateFile), s.requireLocationPortal))
	mux.Handle("/assets/w4-template.pdf", middleware.Chain(http.HandlerFunc(s.w4TemplateFile), s.requireLocationPortal))
	mux.Handle("/employee/photo-upload/", http.HandlerFunc(s.publicPhotoUploadRoutes))
	mux.Handle("/employee/paperwork/", http.HandlerFunc(s.publicEmployeePaperworkRoutes))
	mux.Handle("/interview/", http.HandlerFunc(s.publicInterviewRoutes))
	mux.Handle("/time-punch/", http.HandlerFunc(s.publicTimePunchRoutes))
	mux.Handle("/time-off/", http.HandlerFunc(s.publicTimeOffRoutes))
	mux.Handle("/uniform-order/", http.HandlerFunc(s.publicUniformOrderRoutes))

	csp := strings.Join([]string{
		"default-src 'self'",
		"style-src 'self' https://fonts.googleapis.com 'unsafe-inline'",
		"font-src 'self' https://fonts.gstatic.com",
		"img-src 'self' data:",
		"script-src 'self' 'unsafe-inline'",
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
		ReadHeaderTimeout: cfg.ReadTimeout,
		WriteTimeout:      cfg.WriteTimeout,
	}

	errCh := make(chan error, 1)
	go func() {
		log.Printf("client listening on http://localhost%s", cfg.Addr)
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

func (s *server) loginPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if currentUser, err := s.fetchSessionUser(r); err == nil && currentUser != nil {
		http.Redirect(w, r, redirectPathForUser(currentUser), http.StatusFound)
		return
	}

	data := pageData{Error: r.URL.Query().Get("error")}
	if err := renderHTMLTemplate(w, s.loginTmpl, data); err != nil {
		http.Error(w, "template render failed", http.StatusInternalServerError)
		log.Printf("login template render failed: %v", err)
	}
}

func (s *server) loginRoute(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.loginPage(w, r)
	case http.MethodPost:
		s.login(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *server) logoutRoute(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	sessionValues := []string{
		sessionValueForRole(r, "admin"),
		sessionValueForRole(r, "restaurant"),
		sessionValueForRole(r, "team"),
	}
	for _, sessionValue := range sessionValues {
		if strings.TrimSpace(sessionValue) == "" {
			continue
		}
		csrfToken, err := s.fetchCSRFTokenWithSessionValue(r, sessionValue)
		if err != nil || strings.TrimSpace(csrfToken) == "" {
			continue
		}
		apiReq, reqErr := http.NewRequestWithContext(r.Context(), http.MethodPost, s.apiBaseURL+"/api/auth/logout", nil)
		if reqErr != nil {
			continue
		}
		copySessionCookieHeaderForValue(apiReq, sessionValue)
		apiReq.Header.Set(csrfHeaderName, csrfToken)
		if apiResp, doErr := s.apiClient.Do(apiReq); doErr == nil {
			_ = apiResp.Body.Close()
		}
	}
	expireSessionCookie(w)
	http.Redirect(w, r, "/login", http.StatusFound)
}

func (s *server) teamLoginRoute(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/login", http.StatusFound)
}

func (s *server) teamLoginTokenRoute(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/team-login/"))
	if token == "" {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodGet:
		s.teamLoginPage(w, r, token)
	case http.MethodPost:
		s.teamLogin(w, r, token)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *server) login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/?error=Invalid+form+submission", http.StatusFound)
		return
	}

	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	if username == "" || password == "" {
		http.Redirect(w, r, "/?error=Username+and+password+are+required", http.StatusFound)
		return
	}

	bodyBytes, _ := json.Marshal(map[string]string{"username": username, "password": password})
	apiReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, s.apiBaseURL+"/api/auth/login", bytes.NewReader(bodyBytes))
	if err != nil {
		http.Redirect(w, r, "/?error=Unable+to+authenticate", http.StatusFound)
		return
	}
	apiReq.Header.Set("Content-Type", "application/json")
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		http.Redirect(w, r, "/?error=Authentication+service+unavailable", http.StatusFound)
		return
	}
	defer apiResp.Body.Close()

	if apiResp.StatusCode != http.StatusOK {
		http.Redirect(w, r, "/?error=Invalid+credentials", http.StatusFound)
		return
	}

	sessionValue := extractAPISessionCookieValue(apiResp)
	if strings.TrimSpace(sessionValue) == "" {
		http.Redirect(w, r, "/?error=Authentication+service+unavailable", http.StatusFound)
		return
	}
	user, err := s.fetchSessionUserWithSessionValue(r, sessionValue)
	if err != nil || user == nil {
		http.Redirect(w, r, "/?error=Unable+to+load+session", http.StatusFound)
		return
	}
	role := sessionRoleFromUser(user)
	cookieName := cookieNameForSessionRole(role)
	if cookieName == "" {
		http.Redirect(w, r, "/?error=Unable+to+resolve+session+role", http.StatusFound)
		return
	}
	setScopedSessionCookie(w, cookieName, sessionValue)
	expireSessionCookieByName(w, apiSessionCookie)
	http.Redirect(w, r, "/admin", http.StatusFound)
}

func (s *server) teamLoginPage(w http.ResponseWriter, r *http.Request, token string) {
	// Allow admin/restaurant users to open a team login link without being redirected.
	// Only redirect when there is already an active team session.
	if currentTeamUser, err := s.fetchSessionUserByRoles(r, []string{"team"}); err == nil && currentTeamUser != nil {
		http.Redirect(w, r, "/team", http.StatusFound)
		return
	}
	apiURL := s.apiBaseURL + "/api/public/time-punch/" + url.PathEscape(token)
	apiReq, err := http.NewRequestWithContext(r.Context(), http.MethodGet, apiURL, nil)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer apiResp.Body.Close()
	if apiResp.StatusCode != http.StatusOK {
		http.NotFound(w, r)
		return
	}
	var payload publicTimePunchResponse
	if err := json.NewDecoder(apiResp.Body).Decode(&payload); err != nil {
		http.NotFound(w, r)
		return
	}
	if err := renderHTMLTemplate(w, s.teamLoginTmpl, pageData{
		Token: token,
		Location: &locationView{
			Number: payload.LocationNumber,
			Name:   payload.LocationName,
		},
		Error: r.URL.Query().Get("error"),
	}); err != nil {
		http.Error(w, "template render failed", http.StatusInternalServerError)
		log.Printf("team login template render failed: %v", err)
	}
}

func (s *server) teamLogin(w http.ResponseWriter, r *http.Request, token string) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/team-login/"+url.PathEscape(token)+"?error=Invalid+form+submission", http.StatusFound)
		return
	}
	pin := strings.TrimSpace(r.FormValue("pin"))
	bodyBytes, _ := json.Marshal(map[string]string{
		"token": token,
		"pin":   pin,
	})
	apiReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, s.apiBaseURL+"/api/auth/team-login", bytes.NewReader(bodyBytes))
	if err != nil {
		http.Redirect(w, r, "/team-login/"+url.PathEscape(token)+"?error=Unable+to+authenticate", http.StatusFound)
		return
	}
	apiReq.Header.Set("Content-Type", "application/json")
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		http.Redirect(w, r, "/team-login/"+url.PathEscape(token)+"?error=Authentication+service+unavailable", http.StatusFound)
		return
	}
	defer apiResp.Body.Close()
	if apiResp.StatusCode != http.StatusOK {
		http.Redirect(w, r, "/team-login/"+url.PathEscape(token)+"?error=Invalid+clock+in+pin", http.StatusFound)
		return
	}
	sessionValue := extractAPISessionCookieValue(apiResp)
	if strings.TrimSpace(sessionValue) == "" {
		http.Redirect(w, r, "/team-login/"+url.PathEscape(token)+"?error=Authentication+service+unavailable", http.StatusFound)
		return
	}
	setScopedSessionCookie(w, teamSessionCookie, sessionValue)
	expireSessionCookieByName(w, apiSessionCookie)
	http.Redirect(w, r, "/team", http.StatusFound)
}

func (s *server) adminPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	csrfToken, err := s.fetchCSRFToken(r)
	if err != nil {
		http.Redirect(w, r, "/?error=Session+expired", http.StatusFound)
		return
	}
	page := parsePositiveInt(r.URL.Query().Get("page"), 1)
	list, err := s.fetchLocationsPage(r, page, 25)
	if err != nil {
		http.Error(w, "unable to load locations", http.StatusBadGateway)
		return
	}

	data := pageData{
		CSRF:       csrfToken,
		Page:       list.Page,
		Locations:  list.Locations,
		HasPrev:    list.Page > 1,
		HasNext:    list.Page < list.TotalPages,
		PrevPage:   max(1, list.Page-1),
		NextPage:   list.Page + 1,
		TotalCount: list.Count,
	}
	if err := renderHTMLTemplate(w, s.adminTmpl, data); err != nil {
		http.Error(w, "template render failed", http.StatusInternalServerError)
		log.Printf("admin template render failed: %v", err)
	}
}

func (s *server) teamPortalPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	currentUser, err := s.fetchSessionUserByRoles(r, []string{"team"})
	if err != nil || currentUser == nil {
		http.Redirect(w, r, "/login?error=Session+expired", http.StatusFound)
		return
	}
	if strings.TrimSpace(currentUser.LocationNumber) == "" {
		http.Redirect(w, r, "/login?error=Team+member+is+not+assigned+to+a+location", http.StatusFound)
		return
	}
	csrfToken, err := s.fetchCSRFTokenForRole(r, "team")
	if err != nil || strings.TrimSpace(csrfToken) == "" {
		http.Redirect(w, r, "/login?error=Session+expired", http.StatusFound)
		return
	}
	location, err := s.fetchLocation(r, currentUser.LocationNumber)
	if err != nil {
		http.Redirect(w, r, "/login?error=Unable+to+load+location", http.StatusFound)
		return
	}
	timePunchEntries, err := s.fetchLocationTimePunchEntries(r, currentUser.LocationNumber, false)
	if err != nil {
		http.Error(w, "unable to load your time punch requests", http.StatusBadGateway)
		return
	}
	archivedTimePunchEntries, err := s.fetchLocationTimePunchEntries(r, currentUser.LocationNumber, true)
	if err != nil {
		http.Error(w, "unable to load your archived time punch requests", http.StatusBadGateway)
		return
	}
	timeOffRequests, err := s.fetchLocationTimeOffRequests(r, currentUser.LocationNumber, false)
	if err != nil {
		http.Error(w, "unable to load your vacation requests", http.StatusBadGateway)
		return
	}
	archivedTimeOffRequests, err := s.fetchLocationTimeOffRequests(r, currentUser.LocationNumber, true)
	if err != nil {
		http.Error(w, "unable to load your processed vacation requests", http.StatusBadGateway)
		return
	}
	uniformOrders, err := s.fetchLocationUniformOrders(r, currentUser.LocationNumber, false)
	if err != nil {
		http.Error(w, "unable to load your uniform orders", http.StatusBadGateway)
		return
	}
	archivedUniformOrders, err := s.fetchLocationUniformOrders(r, currentUser.LocationNumber, true)
	if err != nil {
		http.Error(w, "unable to load your archived uniform orders", http.StatusBadGateway)
		return
	}
	uniformItems, err := s.fetchLocationUniformItems(r, currentUser.LocationNumber)
	if err != nil {
		http.Error(w, "unable to load uniform items", http.StatusBadGateway)
		return
	}
	teamDocuments := []teamDocumentView{}
	i9Form, i9Docs, i9History, err := s.fetchEmployeePaperwork(r, currentUser.LocationNumber, currentUser.TimePunchName, false, "i9")
	if err == nil {
		teamDocuments = append(teamDocuments, buildTeamDocumentsFromPaperwork("i9", i9Form, i9Docs, i9History)...)
	}
	w4Form, _, w4History, err := s.fetchEmployeePaperwork(r, currentUser.LocationNumber, currentUser.TimePunchName, false, "w4")
	if err == nil {
		teamDocuments = append(teamDocuments, buildTeamDocumentsFromPaperwork("w4", w4Form, nil, w4History)...)
	}
	teamTimePunchName := strings.TrimSpace(currentUser.TimePunchName)
	inProcessTimePunchEntries := filterEntriesByTeamMember(timePunchEntries, teamTimePunchName)
	completedTimePunchEntries := filterEntriesByTeamMember(archivedTimePunchEntries, teamTimePunchName)
	waitingTimeOffRequests := filterTimeOffByTeamMember(timeOffRequests, teamTimePunchName)
	processedTimeOffRequests := filterTimeOffByTeamMember(archivedTimeOffRequests, teamTimePunchName)
	filteredUniformOrders := append(
		filterUniformOrdersByTeamMember(uniformOrders, teamTimePunchName),
		filterUniformOrdersByTeamMember(archivedUniformOrders, teamTimePunchName)...,
	)
	if err := renderHTMLTemplate(w, s.teamPortalTmpl, pageData{
		CSRF:                     csrfToken,
		CurrentUser:              currentUser,
		Location:                 location,
		UniformItems:             uniformItems,
		TimePunchEntries:         limitTimePunchEntries(inProcessTimePunchEntries, 50),
		ArchivedTimePunchEntries: limitTimePunchEntries(completedTimePunchEntries, 50),
		TimeOffRequests:          limitTimeOffRequests(waitingTimeOffRequests, 50),
		ArchivedTimeOffRequests:  limitTimeOffRequests(processedTimeOffRequests, 50),
		UniformOrders:            limitUniformOrders(filteredUniformOrders, 50),
		TeamDocuments:            teamDocuments,
		SuccessMessage:           r.URL.Query().Get("message"),
		Error:                    r.URL.Query().Get("error"),
	}); err != nil {
		http.Error(w, "template render failed", http.StatusInternalServerError)
		log.Printf("team portal template render failed: %v", err)
	}
}

func (s *server) teamRoutes(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimSpace(r.URL.Path)
	if path == "/team/" && r.Method == http.MethodGet {
		http.Redirect(w, r, "/team", http.StatusFound)
		return
	}
	if r.Method == http.MethodGet && (path == "/team/documents" || strings.HasPrefix(path, "/team/documents/")) {
		s.teamDocumentFileProxy(w, r)
		return
	}
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	switch path {
	case "/team/time-punch":
		s.createTeamTimePunchProxy(w, r)
	case "/team/time-off":
		s.createTeamTimeOffProxy(w, r)
	case "/team/uniform-order":
		s.createTeamUniformOrderProxy(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (s *server) teamDocumentFileProxy(w http.ResponseWriter, r *http.Request) {
	currentUser, err := s.fetchSessionUserByRoles(r, []string{"team"})
	if err != nil || currentUser == nil {
		http.Redirect(w, r, "/login?error=Session+expired", http.StatusFound)
		return
	}
	path := strings.TrimSpace(r.URL.Path)
	locationNumber := strings.TrimSpace(currentUser.LocationNumber)
	timePunchName := strings.TrimSpace(currentUser.TimePunchName)
	if locationNumber == "" || timePunchName == "" {
		http.Redirect(w, r, "/login?error=Session+invalid", http.StatusFound)
		return
	}

	apiPath := ""
	switch {
	case path == "/team/documents/i9/file":
		apiPath = "/api/admin/locations/" + url.PathEscape(locationNumber) + "/employees/" + url.PathEscape(timePunchName) + "/i9/file"
	case path == "/team/documents/w4/file":
		apiPath = "/api/admin/locations/" + url.PathEscape(locationNumber) + "/employees/" + url.PathEscape(timePunchName) + "/w4/file"
	case strings.HasPrefix(path, "/team/documents/i9/supporting/") && strings.HasSuffix(path, "/file"):
		trimmed := strings.TrimPrefix(path, "/team/documents/i9/supporting/")
		trimmed = strings.TrimSuffix(trimmed, "/file")
		trimmed = strings.Trim(trimmed, "/")
		docID, parseErr := strconv.ParseInt(trimmed, 10, 64)
		if parseErr != nil || docID <= 0 {
			http.NotFound(w, r)
			return
		}
		apiPath = "/api/admin/locations/" + url.PathEscape(locationNumber) + "/employees/" + url.PathEscape(timePunchName) + "/i9/documents/" + strconv.FormatInt(docID, 10) + "/file"
	default:
		http.NotFound(w, r)
		return
	}

	apiURL := s.apiBaseURL + apiPath
	if rawQuery := strings.TrimSpace(r.URL.RawQuery); rawQuery != "" {
		apiURL += "?" + rawQuery
	}
	apiReq, err := http.NewRequestWithContext(r.Context(), http.MethodGet, apiURL, nil)
	if err != nil {
		http.Error(w, "upstream request failed", http.StatusInternalServerError)
		return
	}
	copySessionCookieHeader(r, apiReq)

	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		http.Error(w, "upstream service unavailable", http.StatusBadGateway)
		return
	}
	defer apiResp.Body.Close()
	if apiResp.StatusCode != http.StatusOK {
		http.Error(w, "document not found", apiResp.StatusCode)
		return
	}

	if contentType := strings.TrimSpace(apiResp.Header.Get("Content-Type")); contentType != "" {
		w.Header().Set("Content-Type", contentType)
	}
	if contentDisposition := strings.TrimSpace(apiResp.Header.Get("Content-Disposition")); contentDisposition != "" {
		w.Header().Set("Content-Disposition", contentDisposition)
	}
	if cacheControl := strings.TrimSpace(apiResp.Header.Get("Cache-Control")); cacheControl != "" {
		w.Header().Set("Cache-Control", cacheControl)
	}
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, apiResp.Body)
}

func (s *server) createTeamTimePunchProxy(w http.ResponseWriter, r *http.Request) {
	currentUser, err := s.fetchSessionUserByRoles(r, []string{"team"})
	if err != nil || currentUser == nil {
		http.Redirect(w, r, "/login?error=Session+expired", http.StatusFound)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/team?error=Invalid+time+punch+form&app=time-punch&mode=create", http.StatusFound)
		return
	}
	csrfToken := strings.TrimSpace(r.FormValue("csrf_token"))
	if csrfToken == "" {
		http.Redirect(w, r, "/team?error=Missing+csrf+token&app=time-punch&mode=create", http.StatusFound)
		return
	}
	payload := map[string]any{
		"timePunchName":            strings.TrimSpace(currentUser.TimePunchName),
		"punchDate":                strings.TrimSpace(r.FormValue("punch_date")),
		"timeIn":                   strings.TrimSpace(r.FormValue("time_in")),
		"timeOut":                  strings.TrimSpace(r.FormValue("time_out")),
		"note":                     strings.TrimSpace(r.FormValue("note")),
		"forgotBreakClockInReturn": strings.TrimSpace(r.FormValue("forgot_break_clock_in_return")) != "",
	}
	body, _ := json.Marshal(payload)
	apiURL := s.apiBaseURL + "/api/admin/locations/" + url.PathEscape(currentUser.LocationNumber) + "/time-punch"
	apiReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, apiURL, bytes.NewReader(body))
	if err != nil {
		http.Redirect(w, r, "/team?error=Unable+to+submit+time+punch&app=time-punch&mode=create", http.StatusFound)
		return
	}
	copySessionCookieHeader(r, apiReq)
	apiReq.Header.Set("Content-Type", "application/json")
	apiReq.Header.Set(csrfHeaderName, csrfToken)
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		http.Redirect(w, r, "/team?error=Service+unavailable&app=time-punch&mode=create", http.StatusFound)
		return
	}
	defer apiResp.Body.Close()
	respBody, _ := io.ReadAll(apiResp.Body)
	if apiResp.StatusCode != http.StatusCreated && apiResp.StatusCode != http.StatusOK {
		msg := "unable to submit time punch"
		var errPayload map[string]string
		if err := json.Unmarshal(respBody, &errPayload); err == nil && strings.TrimSpace(errPayload["error"]) != "" {
			msg = errPayload["error"]
		}
		http.Redirect(w, r, "/team?error="+url.QueryEscape(msg)+"&app=time-punch&mode=create", http.StatusFound)
		return
	}
	http.Redirect(w, r, "/team?message="+url.QueryEscape("Time punch submitted")+"&app=time-punch&mode=view", http.StatusFound)
}

func (s *server) createTeamTimeOffProxy(w http.ResponseWriter, r *http.Request) {
	currentUser, err := s.fetchSessionUserByRoles(r, []string{"team"})
	if err != nil || currentUser == nil {
		http.Redirect(w, r, "/login?error=Session+expired", http.StatusFound)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/team?error=Invalid+time+off+form&app=time-off&mode=create", http.StatusFound)
		return
	}
	csrfToken := strings.TrimSpace(r.FormValue("csrf_token"))
	if csrfToken == "" {
		http.Redirect(w, r, "/team?error=Missing+csrf+token&app=time-off&mode=create", http.StatusFound)
		return
	}
	startDate := strings.TrimSpace(r.FormValue("start_date"))
	endDate := strings.TrimSpace(r.FormValue("end_date"))
	if endDate == "" {
		endDate = startDate
	}
	payload := map[string]string{
		"timePunchName": strings.TrimSpace(currentUser.TimePunchName),
		"startDate":     startDate,
		"endDate":       endDate,
	}
	body, _ := json.Marshal(payload)
	apiURL := s.apiBaseURL + "/api/admin/locations/" + url.PathEscape(currentUser.LocationNumber) + "/time-off"
	apiReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, apiURL, bytes.NewReader(body))
	if err != nil {
		http.Redirect(w, r, "/team?error=Unable+to+submit+time+off+request&app=time-off&mode=create", http.StatusFound)
		return
	}
	copySessionCookieHeader(r, apiReq)
	apiReq.Header.Set("Content-Type", "application/json")
	apiReq.Header.Set(csrfHeaderName, csrfToken)
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		http.Redirect(w, r, "/team?error=Service+unavailable&app=time-off&mode=create", http.StatusFound)
		return
	}
	defer apiResp.Body.Close()
	respBody, _ := io.ReadAll(apiResp.Body)
	if apiResp.StatusCode != http.StatusCreated && apiResp.StatusCode != http.StatusOK {
		msg := "unable to submit vacation request"
		var errPayload map[string]string
		if err := json.Unmarshal(respBody, &errPayload); err == nil && strings.TrimSpace(errPayload["error"]) != "" {
			msg = errPayload["error"]
		}
		http.Redirect(w, r, "/team?error="+url.QueryEscape(msg)+"&app=time-off&mode=create", http.StatusFound)
		return
	}
	http.Redirect(w, r, "/team?message="+url.QueryEscape("Vacation request submitted")+"&app=time-off&mode=view", http.StatusFound)
}

func (s *server) createTeamUniformOrderProxy(w http.ResponseWriter, r *http.Request) {
	currentUser, err := s.fetchSessionUserByRoles(r, []string{"team"})
	if err != nil || currentUser == nil {
		http.Redirect(w, r, "/login?error=Session+expired", http.StatusFound)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/team?error=Invalid+uniform+order+form&app=uniform&mode=create", http.StatusFound)
		return
	}
	csrfToken := strings.TrimSpace(r.FormValue("csrf_token"))
	if csrfToken == "" {
		http.Redirect(w, r, "/team?error=Missing+csrf+token&app=uniform&mode=create", http.StatusFound)
		return
	}
	orderType := strings.TrimSpace(strings.ToLower(r.FormValue("order_type")))
	itemID := int64(0)
	if orderType != uniformSystemKeyShoes {
		parsedItemID, err := strconv.ParseInt(strings.TrimSpace(r.FormValue("item_id")), 10, 64)
		if err != nil || parsedItemID <= 0 {
			http.Redirect(w, r, "/team?error=Invalid+uniform+item&app=uniform&mode=create", http.StatusFound)
			return
		}
		itemID = parsedItemID
	}
	quantity, err := strconv.ParseInt(strings.TrimSpace(r.FormValue("quantity")), 10, 64)
	if err != nil || quantity <= 0 {
		http.Redirect(w, r, "/team?error=Quantity+must+be+at+least+1&app=uniform&mode=create", http.StatusFound)
		return
	}
	payload := map[string]any{
		"timePunchName": strings.TrimSpace(currentUser.TimePunchName),
		"items": []map[string]any{
			{
				"itemId":         itemID,
				"size":           strings.TrimSpace(r.FormValue("size")),
				"sizeSelections": parseFormSizeSelections(r.PostForm["size_field_label"], r.PostForm["size_field_value"]),
				"sizeValues":     parseFormSizeValues(r.PostForm["size_field_value"]),
				"orderType":      orderType,
				"shoeItemNumber": strings.TrimSpace(r.FormValue("shoe_item_number")),
				"shoePrice":      strings.TrimSpace(r.FormValue("shoe_price")),
				"shoeUrl":        strings.TrimSpace(r.FormValue("shoe_url")),
				"note":           strings.TrimSpace(r.FormValue("note")),
				"quantity":       quantity,
			},
		},
	}
	body, _ := json.Marshal(payload)
	apiURL := s.apiBaseURL + "/api/admin/locations/" + url.PathEscape(currentUser.LocationNumber) + "/uniform-orders"
	apiReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, apiURL, bytes.NewReader(body))
	if err != nil {
		http.Redirect(w, r, "/team?error=Unable+to+submit+uniform+order&app=uniform&mode=create", http.StatusFound)
		return
	}
	copySessionCookieHeader(r, apiReq)
	apiReq.Header.Set("Content-Type", "application/json")
	apiReq.Header.Set(csrfHeaderName, csrfToken)
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		http.Redirect(w, r, "/team?error=Service+unavailable&app=uniform&mode=create", http.StatusFound)
		return
	}
	defer apiResp.Body.Close()
	respBody, _ := io.ReadAll(apiResp.Body)
	if apiResp.StatusCode != http.StatusCreated && apiResp.StatusCode != http.StatusOK {
		msg := "unable to submit uniform order"
		var errPayload map[string]string
		if err := json.Unmarshal(respBody, &errPayload); err == nil && strings.TrimSpace(errPayload["error"]) != "" {
			msg = errPayload["error"]
		}
		http.Redirect(w, r, "/team?error="+url.QueryEscape(msg)+"&app=uniform&mode=create", http.StatusFound)
		return
	}
	http.Redirect(w, r, "/team?message="+url.QueryEscape("Uniform order submitted")+"&app=uniform&mode=view", http.StatusFound)
}

func filterEntriesByTeamMember(entries []timePunchEntryView, timePunchName string) []timePunchEntryView {
	target := strings.ToLower(strings.TrimSpace(timePunchName))
	if target == "" {
		return nil
	}
	filtered := make([]timePunchEntryView, 0, len(entries))
	for _, entry := range entries {
		if strings.ToLower(strings.TrimSpace(entry.TimePunchName)) == target {
			filtered = append(filtered, entry)
		}
	}
	return filtered
}

func filterTimeOffByTeamMember(requests []timeOffRequestView, timePunchName string) []timeOffRequestView {
	target := strings.ToLower(strings.TrimSpace(timePunchName))
	if target == "" {
		return nil
	}
	filtered := make([]timeOffRequestView, 0, len(requests))
	for _, request := range requests {
		if strings.ToLower(strings.TrimSpace(request.TimePunchName)) == target {
			filtered = append(filtered, request)
		}
	}
	return filtered
}

func filterUniformOrdersByTeamMember(orders []uniformOrderView, timePunchName string) []uniformOrderView {
	target := strings.ToLower(strings.TrimSpace(timePunchName))
	if target == "" {
		return nil
	}
	filtered := make([]uniformOrderView, 0, len(orders))
	for _, order := range orders {
		if strings.ToLower(strings.TrimSpace(order.TimePunchName)) == target {
			filtered = append(filtered, order)
		}
	}
	return filtered
}

func parseFormSizeSelections(labels, values []string) map[string]string {
	selections := map[string]string{}
	if len(labels) == 0 || len(values) == 0 {
		return selections
	}
	limit := len(labels)
	if len(values) < limit {
		limit = len(values)
	}
	for i := 0; i < limit; i++ {
		label := strings.TrimSpace(labels[i])
		value := strings.TrimSpace(values[i])
		if label == "" || value == "" {
			continue
		}
		selections[label] = value
	}
	return selections
}

func parseFormSizeValues(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		out = append(out, trimmed)
	}
	return out
}

func parseFormSizeSelectionsForItem(labels, values []string, item *uniformItemView) map[string]string {
	selections := parseFormSizeSelections(labels, values)
	if len(selections) > 0 {
		return selections
	}
	if item == nil || len(item.SizeFields) == 0 || len(values) == 0 {
		return selections
	}
	limit := len(item.SizeFields)
	if len(values) < limit {
		limit = len(values)
	}
	for i := 0; i < limit; i++ {
		label := strings.TrimSpace(item.SizeFields[i].Label)
		value := strings.TrimSpace(values[i])
		if label == "" || value == "" {
			continue
		}
		selections[label] = value
	}
	return selections
}

func limitTimeOffRequests(requests []timeOffRequestView, limit int) []timeOffRequestView {
	if limit <= 0 || len(requests) <= limit {
		return requests
	}
	return requests[:limit]
}

func limitUniformOrders(orders []uniformOrderView, limit int) []uniformOrderView {
	if limit <= 0 || len(orders) <= limit {
		return orders
	}
	return orders[:limit]
}

func uniformOrderStatus(order uniformOrderView) string {
	orderTotalCents := int64(math.Round(order.Total * 100))
	if orderTotalCents <= 0 {
		return "Waiting to be Processed"
	}
	chargedBackCents := int64(0)
	for _, line := range order.Lines {
		chargedBackCents += int64(math.Round(line.ChargedBack * 100))
	}
	if chargedBackCents <= 0 {
		return "Waiting to be Processed"
	}
	if chargedBackCents >= orderTotalCents {
		return "Fully Charged"
	}
	return "Partially Charged"
}

func (s *server) i9TemplateFile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	data, err := os.ReadFile("docs/i9.pdf")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Cache-Control", "private, max-age=300")
	w.Header().Set("Content-Disposition", "inline; filename=\"i9.pdf\"")
	_, _ = w.Write(data)
}

func (s *server) appCSSFile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	data, err := templatesFS.ReadFile("assets/app.css")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Header().Set("Cache-Control", "private, max-age=300")
	_, _ = w.Write(data)
}

func (s *server) uploadDropFile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	data, err := templatesFS.ReadFile("assets/upload-drop.js")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "private, max-age=300")
	_, _ = w.Write(data)
}

func (s *server) shoeIconFile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	data, err := templatesFS.ReadFile("assets/shoe.svg")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "image/svg+xml")
	w.Header().Set("Cache-Control", "private, max-age=300")
	_, _ = w.Write(data)
}

func (s *server) w4TemplateFile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	data, err := os.ReadFile("docs/w4.pdf")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Cache-Control", "private, max-age=300")
	w.Header().Set("Content-Disposition", "inline; filename=\"w4.pdf\"")
	_, _ = w.Write(data)
}

func (s *server) locationDetailPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	rawNumber := strings.TrimPrefix(r.URL.Path, "/admin/locations/")
	rawNumber = strings.TrimSpace(rawNumber)
	if rawNumber == "" || strings.Contains(rawNumber, "/") {
		http.NotFound(w, r)
		return
	}
	locationNumber, err := url.PathUnescape(rawNumber)
	if err != nil || strings.TrimSpace(locationNumber) == "" {
		http.NotFound(w, r)
		return
	}

	location, err := s.fetchLocation(r, locationNumber)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	employees, err := s.fetchLocationEmployees(r, locationNumber)
	if err != nil {
		http.Error(w, "unable to load location employees", http.StatusBadGateway)
		return
	}
	newHireEmployees := make([]employeeView, 0, len(employees))
	for _, employee := range employees {
		if employee.HasCompletedPaperwork {
			continue
		}
		newHireEmployees = append(newHireEmployees, employee)
	}
	employeesMissingProfile := employeesWithMissingRequiredProfileFields(employees)
	departments, err := s.fetchLocationDepartments(r, locationNumber)
	if err != nil {
		http.Error(w, "unable to load departments", http.StatusBadGateway)
		return
	}
	jobs, err := s.fetchLocationJobs(r, locationNumber)
	if err != nil {
		http.Error(w, "unable to load jobs", http.StatusBadGateway)
		return
	}
	openTimePunchEntries, err := s.fetchLocationTimePunchEntries(r, locationNumber, false)
	if err != nil {
		http.Error(w, "unable to load time punch entries", http.StatusBadGateway)
		return
	}
	timeOffRequests, err := s.fetchLocationTimeOffRequests(r, locationNumber, false)
	if err != nil {
		http.Error(w, "unable to load vacation requests", http.StatusBadGateway)
		return
	}
	activeUniformOrders, err := s.fetchLocationUniformOrders(r, locationNumber, false)
	if err != nil {
		http.Error(w, "unable to load uniform orders", http.StatusBadGateway)
		return
	}
	archivedUniformOrders, err := s.fetchLocationUniformOrders(r, locationNumber, true)
	if err != nil {
		http.Error(w, "unable to load archived uniform orders", http.StatusBadGateway)
		return
	}
	activeCandidates, err := s.fetchLocationCandidates(r, locationNumber, false, "")
	if err != nil {
		http.Error(w, "unable to load candidates", http.StatusBadGateway)
		return
	}
	interviewCalendar, err := s.fetchLocationInterviewCalendar(r, locationNumber)
	if err != nil {
		http.Error(w, "unable to load interview calendar", http.StatusBadGateway)
		return
	}
	interviewNames, err := s.fetchLocationCandidateInterviewNames(r, locationNumber)
	if err != nil {
		http.Error(w, "unable to load interview types", http.StatusBadGateway)
		return
	}
	interviewQuestions, err := s.fetchLocationCandidateInterviewQuestions(r, locationNumber)
	if err != nil {
		http.Error(w, "unable to load interview questions", http.StatusBadGateway)
		return
	}
	businessDays, err := s.fetchLocationBusinessDays(r, locationNumber)
	if err != nil {
		http.Error(w, "unable to load business days", http.StatusBadGateway)
		return
	}
	departmentsMissingJobs := departmentsWithoutJobs(departments, jobs)
	hasOverdueTimeOffRequests, overdueTimeOffRequestCount := overdueTimeOffRequestStatus(timeOffRequests, time.Now())
	hasUpcomingTimeOffRequests, upcomingTimeOffRequestCount := upcomingTimeOffRequestStatus(timeOffRequests, time.Now(), 7)
	hasPendingUniformOrders, pendingUniformOrderCount := unpurchasedUniformOrderStatus(activeUniformOrders)
	hasOutstandingUniformCharges, outstandingUniformChargeOrderCount := outstandingUniformChargesStatus(append(append([]uniformOrderView{}, activeUniformOrders...), archivedUniformOrders...))
	hasStaleCandidateInterviews, staleCandidateInterviewCount := staleInterviewStatus(interviewCalendar, time.Now())
	interviewTypesMissingQuestions := interviewTypesWithoutQuestions(interviewNames, interviewQuestions)
	if err := renderHTMLTemplate(w, s.locationAppsTmpl, pageData{
		Location:                           location,
		NewHireEmployees:                   newHireEmployees,
		EmployeesMissingProfile:            employeesMissingProfile,
		HasEmployeesMissingProfile:         len(employeesMissingProfile) > 0,
		EmployeesMissingProfileCount:       len(employeesMissingProfile),
		DepartmentsMissingJobs:             departmentsMissingJobs,
		HasOpenTimePunchEntries:            len(openTimePunchEntries) > 0,
		HasIncompleteBusinessDays:          hasIncompleteBusinessDaysSinceLocationCreation(location.CreatedAt, businessDays, time.Now()),
		HasOverdueTimeOffRequests:          hasOverdueTimeOffRequests,
		OverdueTimeOffRequestCount:         overdueTimeOffRequestCount,
		HasUpcomingTimeOffRequests:         hasUpcomingTimeOffRequests,
		UpcomingTimeOffRequestCount:        upcomingTimeOffRequestCount,
		HasPendingUniformOrders:            hasPendingUniformOrders,
		PendingUniformOrderCount:           pendingUniformOrderCount,
		HasOutstandingUniformCharges:       hasOutstandingUniformCharges,
		OutstandingUniformChargeOrderCount: outstandingUniformChargeOrderCount,
		HasStaleCandidateInterviews:        hasStaleCandidateInterviews,
		StaleCandidateInterviewCount:       staleCandidateInterviewCount,
		HasActiveCandidates:                len(activeCandidates) > 0,
		ActiveCandidateCount:               len(activeCandidates),
		HasInterviewTypes:                  len(interviewNames) > 0,
		InterviewTypesMissingQuestions:     interviewTypesMissingQuestions,
	}); err != nil {
		http.Error(w, "template render failed", http.StatusInternalServerError)
		log.Printf("location apps template render failed: %v", err)
	}
}

func (s *server) locationRoutes(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		if locationNumber, ok := parseLocationSettingsLoginAsLocationPath(r.URL.Path); ok {
			s.loginAsLocationProxy(w, r, locationNumber)
			return
		}
		if locationNumber, timePunchName, ok := parseLocationEmployeeTerminatePath(r.URL.Path); ok {
			s.terminateEmployeeProxy(w, r, locationNumber, timePunchName)
			return
		}
		if locationNumber, timePunchName, ok := parseLocationEmployeeI9UploadPath(r.URL.Path); ok {
			s.uploadEmployeeI9Proxy(w, r, locationNumber, timePunchName)
			return
		}
		if locationNumber, timePunchName, ok := parseLocationEmployeeLoginAsTeamPath(r.URL.Path); ok {
			s.loginAsEmployeeTeamMemberProxy(w, r, locationNumber, timePunchName)
			return
		}
		if locationNumber, timePunchName, ok := parseLocationEmployeeDetailsUpdatePath(r.URL.Path); ok {
			s.updateEmployeeDetailsProxy(w, r, locationNumber, timePunchName)
			return
		}
		if locationNumber, timePunchName, ok := parseLocationEmployeeW4UploadPath(r.URL.Path); ok {
			s.uploadEmployeeW4Proxy(w, r, locationNumber, timePunchName)
			return
		}
		if locationNumber, timePunchName, ok := parseLocationEmployeeI9DocumentUploadPath(r.URL.Path); ok {
			s.uploadEmployeeI9DocumentProxy(w, r, locationNumber, timePunchName)
			return
		}
		if locationNumber, timePunchName, docID, ok := parseLocationEmployeeI9DocumentDeletePath(r.URL.Path); ok {
			s.deleteEmployeeI9DocumentProxy(w, r, locationNumber, timePunchName, docID)
			return
		}
		if locationNumber, orderID, lineID, ok := parseLocationUniformOrderLineSettlementPostPath(r.URL.Path); ok {
			s.updateUniformOrderLineSettlementProxy(w, r, locationNumber, orderID, lineID)
			return
		}
		if locationNumber, orderID, ok := parseLocationUniformOrderDeletePostPath(r.URL.Path); ok {
			s.deleteArchivedUniformOrderProxy(w, r, locationNumber, orderID)
			return
		}
		if locationNumber, orderID, ok := parseLocationUniformOrderArchivePostPath(r.URL.Path); ok {
			s.archiveUniformOrderProxy(w, r, locationNumber, orderID)
			return
		}
		if locationNumber, itemID, imageID, ok := parseLocationUniformItemImageDeletePostPath(r.URL.Path); ok {
			s.deleteUniformItemImageProxy(w, r, locationNumber, itemID, imageID)
			return
		}
		if locationNumber, itemID, ok := parseLocationUniformItemImagesAddPostPath(r.URL.Path); ok {
			s.addUniformItemImagesProxy(w, r, locationNumber, itemID)
			return
		}
		if locationNumber, itemID, imageID, ok := parseLocationUniformImageMovePostPath(r.URL.Path); ok {
			s.moveUniformImageProxy(w, r, locationNumber, itemID, imageID)
			return
		}
		if locationNumber, itemID, ok := parseLocationUniformItemDeletePostPath(r.URL.Path); ok {
			s.deleteUniformItemProxy(w, r, locationNumber, itemID)
			return
		}
		if locationNumber, itemID, ok := parseLocationUniformItemUpdatePostPath(r.URL.Path); ok {
			s.updateUniformItemProxy(w, r, locationNumber, itemID)
			return
		}
		if locationNumber, ok := parseLocationUniformItemsCreatePath(r.URL.Path); ok {
			s.createUniformItemProxy(w, r, locationNumber)
			return
		}
		if locationNumber, ok := parseLocationUniformOrderCreatePath(r.URL.Path); ok {
			s.createUniformOrderProxy(w, r, locationNumber)
			return
		}
		if locationNumber, requestID, ok := parseLocationTimeOffArchivePostPath(r.URL.Path); ok {
			s.archiveTimeOffRequestProxy(w, r, locationNumber, requestID)
			return
		}
		if locationNumber, ok := parseLocationDepartmentCreatePath(r.URL.Path); ok {
			s.createLocationDepartmentProxy(w, r, locationNumber)
			return
		}
		if locationNumber, ok := parseLocationJobCreatePath(r.URL.Path); ok {
			s.createLocationJobProxy(w, r, locationNumber)
			return
		}
		if locationNumber, jobID, ok := parseLocationJobUpdatePath(r.URL.Path); ok {
			s.updateLocationJobProxy(w, r, locationNumber, jobID)
			return
		}
		if locationNumber, jobID, ok := parseLocationJobAssignDepartmentsPath(r.URL.Path); ok {
			s.assignLocationJobDepartmentsProxy(w, r, locationNumber, jobID)
			return
		}
		if locationNumber, ok := parseLocationTimeOffCreatePath(r.URL.Path); ok {
			s.createLocationTimeOffRequestProxy(w, r, locationNumber)
			return
		}
		if locationNumber, ok := parseLocationBusinessDayOpenPath(r.URL.Path); ok {
			s.openBusinessDayInlineProxy(w, r, locationNumber)
			return
		}
		if locationNumber, entryID, ok := parseLocationTimePunchDeletePath(r.URL.Path); ok {
			s.deleteLocationTimePunchEntryProxy(w, r, locationNumber, entryID)
			return
		}
		if locationNumber, entryID, ok := parseLocationTimePunchArchivePostPath(r.URL.Path); ok {
			s.archiveLocationTimePunchEntryProxy(w, r, locationNumber, entryID)
			return
		}
		if locationNumber, ok := parseLocationTimePunchCreatePath(r.URL.Path); ok {
			s.createLocationTimePunchEntryProxy(w, r, locationNumber)
			return
		}
		if locationNumber, ok := parseLocationBusinessDaysPath(r.URL.Path); ok {
			s.openBusinessDayFromPicker(w, r, locationNumber)
			return
		}
		if locationNumber, ok := parseLocationCandidatesCreatePath(r.URL.Path); ok {
			s.createCandidateProxy(w, r, locationNumber)
			return
		}
		if locationNumber, ok := parseLocationCandidateValuesCreatePath(r.URL.Path); ok {
			s.createCandidateValueProxy(w, r, locationNumber)
			return
		}
		if locationNumber, ok := parseLocationCandidateInterviewNamesCreatePath(r.URL.Path); ok {
			s.createCandidateInterviewNameProxy(w, r, locationNumber)
			return
		}
		if locationNumber, ok := parseLocationCandidateInterviewQuestionsCreatePath(r.URL.Path); ok {
			s.createCandidateInterviewQuestionProxy(w, r, locationNumber)
			return
		}
		if locationNumber, ok := parseLocationCandidateInterviewQuestionStartersCreatePath(r.URL.Path); ok {
			s.createCandidateInterviewQuestionStartersProxy(w, r, locationNumber)
			return
		}
		if locationNumber, candidateID, ok := parseLocationCandidateInterviewCreatePath(r.URL.Path); ok {
			s.createCandidateInterviewProxy(w, r, locationNumber, candidateID)
			return
		}
		if locationNumber, candidateID, ok := parseLocationCandidateInterviewLinkCreatePath(r.URL.Path); ok {
			s.createCandidateInterviewLinkProxy(w, r, locationNumber, candidateID)
			return
		}
		if locationNumber, candidateID, ok := parseLocationCandidateInterviewLinksCreatePath(r.URL.Path); ok {
			s.createCandidateInterviewSessionProxy(w, r, locationNumber, candidateID)
			return
		}
		if locationNumber, candidateID, token, ok := parseLocationCandidateInterviewLinkDeletePath(r.URL.Path); ok {
			s.deleteCandidateInterviewLinkProxy(w, r, locationNumber, candidateID, token)
			return
		}
		if locationNumber, candidateID, ok := parseLocationCandidateDecisionPath(r.URL.Path); ok {
			s.updateCandidateDecisionProxy(w, r, locationNumber, candidateID)
			return
		}
		if locationNumber, candidateID, ok := parseLocationCandidateDeletePath(r.URL.Path); ok {
			s.deleteCandidateProxy(w, r, locationNumber, candidateID)
			return
		}
		if locationNumber, valueID, ok := parseLocationCandidateValueDeletePath(r.URL.Path); ok {
			s.deleteCandidateValueProxy(w, r, locationNumber, valueID)
			return
		}
		if locationNumber, nameID, ok := parseLocationCandidateInterviewNameDeletePath(r.URL.Path); ok {
			s.deleteCandidateInterviewNameProxy(w, r, locationNumber, nameID)
			return
		}
		if locationNumber, nameID, ok := parseLocationCandidateInterviewNamePriorityPath(r.URL.Path); ok {
			s.updateCandidateInterviewNamePriorityProxy(w, r, locationNumber, nameID)
			return
		}
		if locationNumber, ok := parseLocationCandidateInterviewNamesReorderPath(r.URL.Path); ok {
			s.reorderCandidateInterviewNamesProxy(w, r, locationNumber)
			return
		}
		if locationNumber, questionID, ok := parseLocationCandidateInterviewQuestionDeletePath(r.URL.Path); ok {
			s.deleteCandidateInterviewQuestionProxy(w, r, locationNumber, questionID)
			return
		}
		if locationNumber, questionID, ok := parseLocationCandidateInterviewQuestionAssignPath(r.URL.Path); ok {
			s.assignCandidateInterviewQuestionProxy(w, r, locationNumber, questionID)
			return
		}
	}
	if r.Method == http.MethodPut {
		if locationNumber, ok := parseLocationSettingsPath(r.URL.Path); ok {
			s.updateLocationSettingsProxy(w, r, locationNumber)
			return
		}
		if locationNumber, businessDate, ok := parseLocationBusinessDayDetailPath(r.URL.Path); ok {
			s.updateBusinessDayProxy(w, r, locationNumber, businessDate)
			return
		}
		if locationNumber, valueID, ok := parseLocationCandidateValueUpdatePath(r.URL.Path); ok {
			s.updateCandidateValueProxy(w, r, locationNumber, valueID)
			return
		}
	}
	if strings.Contains(r.URL.Path, "/employees/") && strings.HasSuffix(r.URL.Path, "/photo-link") {
		s.createEmployeePhotoLinkProxy(w, r)
		return
	}
	if strings.Contains(r.URL.Path, "/employees/") && strings.HasSuffix(r.URL.Path, "/paperwork-link") {
		s.createEmployeePaperworkLinkProxy(w, r)
		return
	}
	if strings.Contains(r.URL.Path, "/employees/") && strings.HasSuffix(r.URL.Path, "/i9/file") {
		s.getEmployeeI9FileProxy(w, r)
		return
	}
	if strings.Contains(r.URL.Path, "/employees/") && strings.HasSuffix(r.URL.Path, "/w4/file") {
		s.getEmployeeW4FileProxy(w, r)
		return
	}
	if strings.Contains(r.URL.Path, "/employees/") && strings.Contains(r.URL.Path, "/i9/documents/") {
		s.getEmployeeI9DocumentFileProxy(w, r)
		return
	}
	if strings.Contains(r.URL.Path, "/employees/") && strings.HasSuffix(r.URL.Path, "/photo") {
		if r.Method == http.MethodGet {
			s.getEmployeePhotoProxy(w, r)
		} else if r.Method == http.MethodPost {
			s.uploadEmployeePhotoProxy(w, r)
		} else {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
		return
	}
	if strings.Contains(r.URL.Path, "/employees/") && strings.HasSuffix(r.URL.Path, "/department") {
		s.updateEmployeeDepartmentProxy(w, r)
		return
	}
	if strings.Contains(r.URL.Path, "/employees/") && strings.HasSuffix(r.URL.Path, "/pay-band") {
		s.updateEmployeePayBandProxy(w, r)
		return
	}
	if strings.Contains(r.URL.Path, "/employees/") && strings.HasSuffix(r.URL.Path, "/job") {
		s.updateEmployeeJobProxy(w, r)
		return
	}
	if strings.Contains(r.URL.Path, "/employees/") && strings.Contains(r.URL.Path, "/additional-compensations/") {
		if r.Method == http.MethodPost {
			s.employeeAdditionalCompensationProxy(w, r)
			return
		}
	}
	if strings.Contains(r.URL.Path, "/employees/") && strings.HasSuffix(r.URL.Path, "/clock-in-pin") {
		s.updateEmployeeClockInPINProxy(w, r)
		return
	}
	if strings.HasSuffix(r.URL.Path, "/employees/birthdates/import") {
		s.importLocationBirthdatesProxy(w, r)
		return
	}
	if strings.HasSuffix(r.URL.Path, "/employees/import") {
		s.importLocationEmployeesProxy(w, r)
		return
	}
	if r.Method == http.MethodGet {
		if locationNumber, ok := parseLocationUniformOrdersArchivedPath(r.URL.Path); ok {
			s.locationArchivedUniformOrdersPage(w, r, locationNumber)
			return
		}
		if locationNumber, itemID, ok := parseLocationUniformItemPath(r.URL.Path); ok {
			s.locationUniformItemPage(w, r, locationNumber, itemID)
			return
		}
		if locationNumber, timePunchName, ok := parseArchivedLocationEmployeePath(r.URL.Path); ok {
			s.archivedEmployeeDetailPage(w, r, locationNumber, timePunchName)
			return
		}
		if locationNumber, ok := parseArchivedLocationEmployeesPath(r.URL.Path); ok {
			s.archivedLocationEmployeesPage(w, r, locationNumber)
			return
		}
		if locationNumber, timePunchName, ok := parseLocationEmployeePath(r.URL.Path); ok {
			s.employeeDetailPage(w, r, locationNumber, timePunchName)
			return
		}
		if locationNumber, ok := parseLocationUniformsPath(r.URL.Path); ok {
			s.locationUniformsPage(w, r, locationNumber)
			return
		}
		if locationNumber, ok := parseLocationTimePunchPath(r.URL.Path); ok {
			s.locationTimePunchPage(w, r, locationNumber)
			return
		}
		if locationNumber, ok := parseLocationTimeOffPath(r.URL.Path); ok {
			s.locationTimeOffPage(w, r, locationNumber)
			return
		}
		if locationNumber, ok := parseLocationBusinessDaysPath(r.URL.Path); ok {
			s.locationBusinessDaysPage(w, r, locationNumber)
			return
		}
		if locationNumber, ok := parseLocationSettingsPath(r.URL.Path); ok {
			s.locationSettingsPage(w, r, locationNumber)
			return
		}
		if locationNumber, ok := parseLocationDepartmentsPath(r.URL.Path); ok {
			s.locationDepartmentsPage(w, r, locationNumber)
			return
		}
		if locationNumber, businessDate, ok := parseLocationBusinessDayDetailPath(r.URL.Path); ok {
			s.locationBusinessDayPage(w, r, locationNumber, businessDate)
			return
		}
		if locationNumber, ok := parseLocationEmployeesPath(r.URL.Path); ok {
			s.locationEmployeesPage(w, r, locationNumber)
			return
		}
		if locationNumber, candidateID, ok := parseLocationCandidateScorecardPath(r.URL.Path); ok {
			s.candidateScorecardPage(w, r, locationNumber, candidateID)
			return
		}
		if locationNumber, candidateID, interviewID, ok := parseLocationCandidateInterviewDetailPath(r.URL.Path); ok {
			s.candidateInterviewDetailPage(w, r, locationNumber, candidateID, interviewID)
			return
		}
		if locationNumber, candidateID, token, ok := parseLocationCandidateInterviewLinkDetailPath(r.URL.Path); ok {
			s.candidateInterviewLinkPage(w, r, locationNumber, candidateID, token)
			return
		}
		if locationNumber, candidateID, ok := parseLocationCandidateDetailPath(r.URL.Path); ok {
			s.candidateDetailPage(w, r, locationNumber, candidateID)
			return
		}
		if locationNumber, ok := parseLocationInterviewProcessPath(r.URL.Path); ok {
			s.locationInterviewProcessPage(w, r, locationNumber)
			return
		}
		if locationNumber, ok := parseLocationCandidatesPath(r.URL.Path); ok {
			s.locationCandidatesPage(w, r, locationNumber)
			return
		}
	}
	if r.Method == http.MethodPut {
		s.updateLocationProxy(w, r)
		return
	}
	if r.Method == http.MethodDelete {
		s.deleteLocationProxy(w, r)
		return
	}
	s.locationDetailPage(w, r)
}

func (s *server) locationEmployeesPage(w http.ResponseWriter, r *http.Request, locationNumber string) {
	location, err := s.fetchLocation(r, locationNumber)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	csrfToken, err := s.fetchCSRFToken(r)
	if err != nil {
		http.Redirect(w, r, "/?error=Session+expired", http.StatusFound)
		return
	}
	employees, err := s.fetchLocationEmployees(r, locationNumber)
	if err != nil {
		http.Error(w, "unable to load location employees", http.StatusBadGateway)
		return
	}
	terminatedEmployees, err := s.fetchArchivedLocationEmployees(r, locationNumber)
	if err != nil {
		http.Error(w, "unable to load terminated employees", http.StatusBadGateway)
		return
	}
	activeEmployees := make([]employeeView, 0, len(employees))
	newHireEmployees := make([]employeeView, 0, len(employees))
	for _, employee := range employees {
		if employee.HasCompletedPaperwork {
			activeEmployees = append(activeEmployees, employee)
			continue
		}
		newHireEmployees = append(newHireEmployees, employee)
	}
	employeesMissingProfile := employeesWithMissingRequiredProfileFields(employees)
	jobs, err := s.fetchLocationJobs(r, locationNumber)
	if err != nil {
		http.Error(w, "unable to load jobs", http.StatusBadGateway)
		return
	}
	departments, err := s.fetchLocationDepartments(r, locationNumber)
	if err != nil {
		http.Error(w, "unable to load departments", http.StatusBadGateway)
		return
	}

	if err := renderHTMLTemplate(w, s.locationTmpl, pageData{
		Location:                     location,
		CSRF:                         csrfToken,
		Employees:                    employees,
		ActiveEmployees:              activeEmployees,
		NewHireEmployees:             newHireEmployees,
		EmployeesMissingProfile:      employeesMissingProfile,
		HasEmployeesMissingProfile:   len(employeesMissingProfile) > 0,
		EmployeesMissingProfileCount: len(employeesMissingProfile),
		ArchivedEmployees:            terminatedEmployees,
		LocationDepartments:          departments,
		LocationJobs:                 jobs,
		SuccessMessage:               r.URL.Query().Get("message"),
		Error:                        r.URL.Query().Get("error"),
	}); err != nil {
		http.Error(w, "template render failed", http.StatusInternalServerError)
		log.Printf("location template render failed: %v", err)
	}
}

func (s *server) locationSettingsPage(w http.ResponseWriter, r *http.Request, locationNumber string) {
	location, err := s.fetchLocation(r, locationNumber)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	csrfToken, err := s.fetchCSRFToken(r)
	if err != nil {
		http.Redirect(w, r, "/?error=Session+expired", http.StatusFound)
		return
	}
	settings, err := s.fetchLocationSettings(r, locationNumber)
	if err != nil {
		http.Error(w, "unable to load location settings", http.StatusBadGateway)
		return
	}
	currentUser, _ := s.fetchSessionUserByRoles(r, []string{"admin", "restaurant"})
	teamLoginLink := ""
	if token, err := s.fetchLocationTimePunchToken(r, locationNumber); err == nil && strings.TrimSpace(token) != "" {
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		teamLoginLink = scheme + "://" + r.Host + "/team-login/" + url.PathEscape(token)
	}
	if err := renderHTMLTemplate(w, s.locationSettingsTmpl, pageData{
		Location:         location,
		CSRF:             csrfToken,
		LocationSettings: settings,
		TeamLoginLink:    teamLoginLink,
		CurrentUser:      currentUser,
		SuccessMessage:   r.URL.Query().Get("message"),
		Error:            r.URL.Query().Get("error"),
	}); err != nil {
		http.Error(w, "template render failed", http.StatusInternalServerError)
		log.Printf("location settings template render failed: %v", err)
	}
}

func (s *server) locationDepartmentsPage(w http.ResponseWriter, r *http.Request, locationNumber string) {
	location, err := s.fetchLocation(r, locationNumber)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	csrfToken, err := s.fetchCSRFToken(r)
	if err != nil {
		http.Redirect(w, r, "/?error=Session+expired", http.StatusFound)
		return
	}
	departments, err := s.fetchLocationDepartments(r, locationNumber)
	if err != nil {
		http.Error(w, "unable to load departments", http.StatusBadGateway)
		return
	}
	jobs, err := s.fetchLocationJobs(r, locationNumber)
	if err != nil {
		http.Error(w, "unable to load jobs", http.StatusBadGateway)
		return
	}
	departmentsMissingJobs := departmentsWithoutJobs(departments, jobs)
	if err := renderHTMLTemplate(w, s.departmentsTmpl, pageData{
		Location:               location,
		CSRF:                   csrfToken,
		LocationDepartments:    departments,
		LocationJobs:           jobs,
		DepartmentsMissingJobs: departmentsMissingJobs,
		SuccessMessage:         r.URL.Query().Get("message"),
		Error:                  r.URL.Query().Get("error"),
	}); err != nil {
		http.Error(w, "template render failed", http.StatusInternalServerError)
		log.Printf("departments template render failed: %v", err)
	}
}

func departmentsWithoutJobs(departments []departmentView, jobs []jobView) []string {
	return nil
}

func hasIncompleteBusinessDaysSinceLocationCreation(locationCreatedAt string, businessDays []businessDayView, now time.Time) bool {
	createdAt, ok := parseLocationCreatedAt(locationCreatedAt)
	if !ok {
		return false
	}
	locationStart := time.Date(createdAt.Year(), createdAt.Month(), createdAt.Day(), 0, 0, 0, 0, now.Location())
	todayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	checkEnd := todayStart.AddDate(0, 0, -1)
	if locationStart.After(checkEnd) {
		return false
	}

	completedByDate := make(map[string]bool, len(businessDays))
	for _, businessDay := range businessDays {
		dateKey := strings.TrimSpace(businessDay.BusinessDate)
		if dateKey == "" {
			continue
		}
		completedByDate[dateKey] = businessDay.TotalSales > 0 && businessDay.LaborHours > 0
	}

	for date := locationStart; !date.After(checkEnd); date = date.AddDate(0, 0, 1) {
		if date.Weekday() == time.Sunday {
			continue
		}
		dateKey := date.Format("2006-01-02")
		completed, exists := completedByDate[dateKey]
		if !exists || !completed {
			return true
		}
	}
	return false
}

func parseLocationCreatedAt(value string) (time.Time, bool) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return time.Time{}, false
	}
	layouts := []string{
		"Jan 2, 2006 3:04 PM",
		"Jan 2, 2006",
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05",
		"2006-01-02 15:04",
		"2006-01-02",
	}
	for _, layout := range layouts {
		parsed, err := time.Parse(layout, trimmed)
		if err != nil {
			continue
		}
		return parsed.In(time.Local), true
	}
	return time.Time{}, false
}

func overdueTimeOffRequestStatus(requests []timeOffRequestView, now time.Time) (bool, int) {
	if len(requests) == 0 {
		return false, 0
	}
	todayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	overdueCutoff := todayStart.AddDate(0, 0, -7)
	overdueCount := 0
	for _, request := range requests {
		endDateText := strings.TrimSpace(request.EndDate)
		if endDateText == "" {
			continue
		}
		endDate, err := time.Parse("2006-01-02", endDateText)
		if err != nil {
			continue
		}
		endDateStart := time.Date(endDate.Year(), endDate.Month(), endDate.Day(), 0, 0, 0, 0, now.Location())
		if !endDateStart.After(overdueCutoff) {
			overdueCount++
		}
	}
	return overdueCount > 0, overdueCount
}

func upcomingTimeOffRequestStatus(requests []timeOffRequestView, now time.Time, upcomingDays int) (bool, int) {
	if len(requests) == 0 || upcomingDays <= 0 {
		return false, 0
	}
	todayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	upcomingEnd := todayStart.AddDate(0, 0, upcomingDays)
	upcomingCount := 0
	for _, request := range requests {
		startDate, err := time.Parse("2006-01-02", strings.TrimSpace(request.StartDate))
		if err != nil {
			continue
		}
		endDate, err := time.Parse("2006-01-02", strings.TrimSpace(request.EndDate))
		if err != nil {
			continue
		}
		startDate = time.Date(startDate.Year(), startDate.Month(), startDate.Day(), 0, 0, 0, 0, now.Location())
		endDate = time.Date(endDate.Year(), endDate.Month(), endDate.Day(), 0, 0, 0, 0, now.Location())
		if endDate.Before(todayStart) {
			continue
		}
		if startDate.After(upcomingEnd) {
			continue
		}
		upcomingCount++
	}
	return upcomingCount > 0, upcomingCount
}

func outstandingUniformChargesStatus(orders []uniformOrderView) (bool, int) {
	outstandingOrders := 0
	for _, order := range orders {
		hasOutstanding := false
		for _, line := range order.Lines {
			if line.Remaining > 0.009 {
				hasOutstanding = true
				break
			}
		}
		if hasOutstanding {
			outstandingOrders++
		}
	}
	return outstandingOrders > 0, outstandingOrders
}

func unpurchasedUniformOrderStatus(orders []uniformOrderView) (bool, int) {
	unpurchasedOrders := 0
	for _, order := range orders {
		hasUnpurchased := false
		for _, line := range order.Lines {
			if !line.Purchased {
				hasUnpurchased = true
				break
			}
		}
		if hasUnpurchased {
			unpurchasedOrders++
		}
	}
	return unpurchasedOrders > 0, unpurchasedOrders
}

func staleInterviewStatus(entries []interviewCalendarEntryView, now time.Time) (bool, int) {
	if len(entries) == 0 {
		return false, 0
	}
	cutoff := now.Add(-4 * time.Hour)
	staleCount := 0
	for _, entry := range entries {
		if strings.TrimSpace(entry.UsedAt) != "" {
			continue
		}
		scheduledAt, ok := parseDateTimeValue(entry.ScheduledAt)
		if !ok {
			continue
		}
		if !scheduledAt.After(cutoff) {
			staleCount++
		}
	}
	return staleCount > 0, staleCount
}

func parseDateTimeValue(value string) (time.Time, bool) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return time.Time{}, false
	}
	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05",
		"2006-01-02 15:04",
		"Jan 2, 2006 3:04 PM",
		"Jan 2, 2006",
	}
	for _, layout := range layouts {
		parsed, err := time.Parse(layout, trimmed)
		if err != nil {
			continue
		}
		return parsed.In(time.Local), true
	}
	return time.Time{}, false
}

func interviewTypesWithoutQuestions(interviewNames []candidateInterviewNameView, interviewQuestions []candidateInterviewQuestionView) []string {
	if len(interviewNames) == 0 {
		return nil
	}
	hasQuestions := make(map[int64]bool, len(interviewNames))
	for _, question := range interviewQuestions {
		if len(question.InterviewNameIDs) > 0 {
			for _, nameID := range question.InterviewNameIDs {
				if nameID > 0 {
					hasQuestions[nameID] = true
				}
			}
			continue
		}
		if question.InterviewNameID > 0 {
			hasQuestions[question.InterviewNameID] = true
		}
	}
	missing := make([]string, 0, len(interviewNames))
	for _, interviewName := range interviewNames {
		if interviewName.ID <= 0 || hasQuestions[interviewName.ID] {
			continue
		}
		name := strings.TrimSpace(interviewName.Name)
		if name == "" {
			continue
		}
		missing = append(missing, name)
	}
	return missing
}

func (s *server) locationCandidatesPage(w http.ResponseWriter, r *http.Request, locationNumber string) {
	location, err := s.fetchLocation(r, locationNumber)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	csrfToken, err := s.fetchCSRFToken(r)
	if err != nil {
		http.Redirect(w, r, "/?error=Session+expired", http.StatusFound)
		return
	}
	candidates, err := s.fetchLocationCandidates(r, locationNumber, false, "")
	if err != nil {
		http.Error(w, "unable to load candidates", http.StatusBadGateway)
		return
	}
	archiveSearch := strings.TrimSpace(r.URL.Query().Get("archive_search"))
	archived, err := s.fetchLocationCandidates(r, locationNumber, true, archiveSearch)
	if err != nil {
		http.Error(w, "unable to load archived candidates", http.StatusBadGateway)
		return
	}
	sort.SliceStable(archived, func(i, j int) bool {
		lastI := strings.ToLower(strings.TrimSpace(archived[i].LastName))
		lastJ := strings.ToLower(strings.TrimSpace(archived[j].LastName))
		if lastI == lastJ {
			firstI := strings.ToLower(strings.TrimSpace(archived[i].FirstName))
			firstJ := strings.ToLower(strings.TrimSpace(archived[j].FirstName))
			if firstI == firstJ {
				return archived[i].ID < archived[j].ID
			}
			return firstI < firstJ
		}
		return lastI < lastJ
	})
	calendarEntries, err := s.fetchLocationInterviewCalendar(r, locationNumber)
	if err != nil {
		http.Error(w, "unable to load interview calendar", http.StatusBadGateway)
		return
	}
	hasStaleCandidateInterviews, staleCandidateInterviewCount := staleInterviewStatus(calendarEntries, time.Now())
	if err := renderHTMLTemplate(w, s.candidatesTmpl, pageData{
		Location:                     location,
		CSRF:                         csrfToken,
		Candidates:                   candidates,
		ArchivedCandidates:           archived,
		InterviewCalendar:            calendarEntries,
		HasStaleCandidateInterviews:  hasStaleCandidateInterviews,
		StaleCandidateInterviewCount: staleCandidateInterviewCount,
		HasActiveCandidates:          len(candidates) > 0,
		ActiveCandidateCount:         len(candidates),
		Search:                       archiveSearch,
		SuccessMessage:               r.URL.Query().Get("message"),
		Error:                        r.URL.Query().Get("error"),
	}); err != nil {
		http.Error(w, "template render failed", http.StatusInternalServerError)
		log.Printf("candidates template render failed: %v", err)
	}
}

func (s *server) locationInterviewProcessPage(w http.ResponseWriter, r *http.Request, locationNumber string) {
	location, err := s.fetchLocation(r, locationNumber)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	csrfToken, err := s.fetchCSRFToken(r)
	if err != nil {
		http.Redirect(w, r, "/?error=Session+expired", http.StatusFound)
		return
	}
	values, err := s.fetchLocationCandidateValues(r, locationNumber)
	if err != nil {
		http.Error(w, "unable to load candidate values", http.StatusBadGateway)
		return
	}
	interviewNames, err := s.fetchLocationCandidateInterviewNames(r, locationNumber)
	if err != nil {
		http.Error(w, "unable to load interview types", http.StatusBadGateway)
		return
	}
	interviewQuestions, err := s.fetchLocationCandidateInterviewQuestions(r, locationNumber)
	if err != nil {
		http.Error(w, "unable to load interview questions", http.StatusBadGateway)
		return
	}
	interviewTypesMissingQuestions := interviewTypesWithoutQuestions(interviewNames, interviewQuestions)
	if err := renderHTMLTemplate(w, s.interviewProcessTmpl, pageData{
		Location:                       location,
		CSRF:                           csrfToken,
		CandidateValues:                values,
		InterviewNames:                 interviewNames,
		InterviewQuestions:             interviewQuestions,
		InterviewQuestionStarters:      interviewQuestionStarterCatalogViews(),
		HasInterviewTypes:              len(interviewNames) > 0,
		InterviewTypesMissingQuestions: interviewTypesMissingQuestions,
		SuccessMessage:                 r.URL.Query().Get("message"),
		Error:                          r.URL.Query().Get("error"),
	}); err != nil {
		http.Error(w, "template render failed", http.StatusInternalServerError)
		log.Printf("interview process template render failed: %v", err)
	}
}

func (s *server) candidateScorecardPage(w http.ResponseWriter, r *http.Request, locationNumber string, candidateID int64) {
	location, err := s.fetchLocation(r, locationNumber)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	candidate, err := s.fetchLocationCandidate(r, locationNumber, candidateID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if err := renderHTMLTemplate(w, s.candidateScorecardTmpl, pageData{
		Location:  location,
		Candidate: candidate,
		Error:     r.URL.Query().Get("error"),
	}); err != nil {
		http.Error(w, "template render failed", http.StatusInternalServerError)
		log.Printf("candidate scorecard template render failed: %v", err)
	}
}

func (s *server) candidateDetailPage(w http.ResponseWriter, r *http.Request, locationNumber string, candidateID int64) {
	location, err := s.fetchLocation(r, locationNumber)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	csrfToken, err := s.fetchCSRFToken(r)
	if err != nil {
		http.Redirect(w, r, "/?error=Session+expired", http.StatusFound)
		return
	}
	candidate, err := s.fetchLocationCandidate(r, locationNumber, candidateID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	values, err := s.fetchLocationCandidateValues(r, locationNumber)
	if err != nil {
		http.Error(w, "unable to load candidate values", http.StatusBadGateway)
		return
	}
	interviewNames, err := s.fetchLocationCandidateInterviewNames(r, locationNumber)
	if err != nil {
		http.Error(w, "unable to load interview types", http.StatusBadGateway)
		return
	}
	interviewers, err := s.fetchLocationEmployees(r, locationNumber)
	if err != nil {
		http.Error(w, "unable to load interviewers", http.StatusBadGateway)
		return
	}
	if len(interviewers) == 0 {
		settings, settingsErr := s.fetchLocationSettings(r, locationNumber)
		if settingsErr != nil {
			http.Error(w, "unable to load interviewer fallback", http.StatusBadGateway)
			return
		}
		ownerOperator := strings.TrimSpace(settings.EmployerRepSignature)
		if ownerOperator == "" {
			ownerOperator = "Owner/Operator"
		}
		interviewers = append(interviewers, employeeView{
			FirstName:     ownerOperator,
			LastName:      "",
			TimePunchName: ownerOperator,
		})
	}
	interviewLinks, err := s.fetchCandidateInterviewLinks(r, locationNumber, candidateID)
	if err != nil {
		http.Error(w, "unable to load interview links", http.StatusBadGateway)
		return
	}
	// Defensive fallback: include calendar-backed interview sessions for this candidate.
	// This keeps the candidate "View Interviews" list in sync with the calendar view.
	calendarEntries, calendarErr := s.fetchLocationInterviewCalendar(r, locationNumber)
	if calendarErr == nil {
		seen := make(map[string]struct{}, len(interviewLinks))
		for i := range interviewLinks {
			token := strings.TrimSpace(interviewLinks[i].Token)
			if token == "" {
				continue
			}
			seen[token] = struct{}{}
		}
		for i := range calendarEntries {
			if calendarEntries[i].CandidateID != candidateID {
				continue
			}
			token := strings.TrimSpace(calendarEntries[i].Token)
			if token == "" {
				continue
			}
			if _, exists := seen[token]; exists {
				continue
			}
			fallback := candidateInterviewLinkView{
				Token:                    token,
				LocationNumber:           locationNumber,
				CandidateID:              candidateID,
				InterviewerTimePunchName: calendarEntries[i].InterviewerTimePunchName,
				InterviewType:            calendarEntries[i].InterviewType,
				ScheduledAt:              calendarEntries[i].ScheduledAt,
				Link:                     "/interview/" + token,
				UsedAt:                   calendarEntries[i].UsedAt,
				CreatedAt:                calendarEntries[i].CreatedAt,
			}
			normalizeCandidateInterviewLinkView(&fallback)
			interviewLinks = append(interviewLinks, fallback)
			seen[token] = struct{}{}
		}
		sort.Slice(interviewLinks, func(i, j int) bool {
			left := strings.TrimSpace(interviewLinks[i].ScheduledAt)
			right := strings.TrimSpace(interviewLinks[j].ScheduledAt)
			if left == right {
				return strings.TrimSpace(interviewLinks[i].CreatedAt) > strings.TrimSpace(interviewLinks[j].CreatedAt)
			}
			return left > right
		})
	}
	jobs, err := s.fetchLocationJobs(r, locationNumber)
	if err != nil {
		http.Error(w, "unable to load jobs", http.StatusBadGateway)
		return
	}
	departments, err := s.fetchLocationDepartments(r, locationNumber)
	if err != nil {
		http.Error(w, "unable to load departments", http.StatusBadGateway)
		return
	}
	if err := renderHTMLTemplate(w, s.candidateDetailTmpl, pageData{
		Location:            location,
		CSRF:                csrfToken,
		Candidate:           candidate,
		CandidateValues:     values,
		InterviewNames:      interviewNames,
		InterviewLinks:      interviewLinks,
		Employees:           interviewers,
		LocationDepartments: departments,
		LocationJobs:        jobs,
		SuccessMessage:      r.URL.Query().Get("message"),
		Error:               r.URL.Query().Get("error"),
	}); err != nil {
		http.Error(w, "template render failed", http.StatusInternalServerError)
		log.Printf("candidate detail template render failed: %v", err)
	}
}

func (s *server) candidateInterviewLinkPage(w http.ResponseWriter, r *http.Request, locationNumber string, candidateID int64, token string) {
	location, err := s.fetchLocation(r, locationNumber)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	candidate, err := s.fetchLocationCandidate(r, locationNumber, candidateID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	linkRecord, err := s.fetchCandidateInterviewLink(r, locationNumber, candidateID, token)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if strings.HasPrefix(linkRecord.Link, "/") {
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		linkRecord.Link = scheme + "://" + r.Host + linkRecord.Link
	}
	if err := renderHTMLTemplate(w, s.candidateInterviewLinkTmpl, pageData{
		Location:      location,
		Candidate:     candidate,
		InterviewLink: linkRecord,
		Error:         r.URL.Query().Get("error"),
	}); err != nil {
		http.Error(w, "template render failed", http.StatusInternalServerError)
		log.Printf("candidate interview link template render failed: %v", err)
	}
}

func (s *server) candidateInterviewDetailPage(w http.ResponseWriter, r *http.Request, locationNumber string, candidateID, interviewID int64) {
	location, err := s.fetchLocation(r, locationNumber)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	candidate, err := s.fetchLocationCandidate(r, locationNumber, candidateID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	var interview *candidateInterviewView
	for i := range candidate.Interviews {
		if candidate.Interviews[i].ID == interviewID {
			interview = &candidate.Interviews[i]
			break
		}
	}
	if interview == nil {
		http.NotFound(w, r)
		return
	}
	if err := renderHTMLTemplate(w, s.candidateInterviewTmpl, pageData{
		Location:  location,
		Candidate: candidate,
		Interview: interview,
		Error:     r.URL.Query().Get("error"),
	}); err != nil {
		http.Error(w, "template render failed", http.StatusInternalServerError)
		log.Printf("candidate interview template render failed: %v", err)
	}
}

func (s *server) createCandidateProxy(w http.ResponseWriter, r *http.Request, locationNumber string) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/candidates?error=Invalid+form+submission", http.StatusFound)
		return
	}
	csrfToken := strings.TrimSpace(r.FormValue("csrf_token"))
	if csrfToken == "" {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/candidates?error=Missing+csrf+token", http.StatusFound)
		return
	}
	payload := map[string]string{
		"firstName": strings.TrimSpace(r.FormValue("first_name")),
		"lastName":  strings.TrimSpace(r.FormValue("last_name")),
		"phone":     strings.TrimSpace(r.FormValue("phone")),
	}
	if strings.TrimSpace(payload["phone"]) == "" {
		phonePart1 := strings.TrimSpace(r.FormValue("phone_1"))
		phonePart2 := strings.TrimSpace(r.FormValue("phone_2"))
		phonePart3 := strings.TrimSpace(r.FormValue("phone_3"))
		if phonePart1 != "" || phonePart2 != "" || phonePart3 != "" {
			payload["phone"] = phonePart1 + "-" + phonePart2 + "-" + phonePart3
		}
	}
	body, _ := json.Marshal(payload)
	apiReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, s.apiBaseURL+"/api/admin/locations/"+url.PathEscape(locationNumber)+"/candidates", bytes.NewReader(body))
	if err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/candidates?error=Unable+to+create+candidate", http.StatusFound)
		return
	}
	copySessionCookieHeader(r, apiReq)
	apiReq.Header.Set("Content-Type", "application/json")
	apiReq.Header.Set(csrfHeaderName, csrfToken)
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/candidates?error=Service+unavailable", http.StatusFound)
		return
	}
	defer apiResp.Body.Close()
	respBody, _ := io.ReadAll(apiResp.Body)
	if apiResp.StatusCode != http.StatusCreated && apiResp.StatusCode != http.StatusOK {
		msg := "unable to create candidate"
		var errPayload map[string]string
		if err := json.Unmarshal(respBody, &errPayload); err == nil && strings.TrimSpace(errPayload["error"]) != "" {
			msg = errPayload["error"]
		}
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/candidates?error="+url.QueryEscape(msg), http.StatusFound)
		return
	}
	http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/candidates?message="+url.QueryEscape("Candidate created"), http.StatusFound)
}

func (s *server) createCandidateValueProxy(w http.ResponseWriter, r *http.Request, locationNumber string) {
	basePath := "/admin/locations/" + url.PathEscape(locationNumber) + "/interview-process"
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, basePath+"?error=Invalid+form+submission&process=values", http.StatusFound)
		return
	}
	csrfToken := strings.TrimSpace(r.FormValue("csrf_token"))
	if csrfToken == "" {
		http.Redirect(w, r, basePath+"?error=Missing+csrf+token&process=values", http.StatusFound)
		return
	}
	payload := map[string]string{
		"name":        strings.TrimSpace(r.FormValue("name")),
		"description": strings.TrimSpace(r.FormValue("description")),
	}
	body, _ := json.Marshal(payload)
	apiReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, s.apiBaseURL+"/api/admin/locations/"+url.PathEscape(locationNumber)+"/candidate-values", bytes.NewReader(body))
	if err != nil {
		http.Redirect(w, r, basePath+"?error=Unable+to+create+value&process=values", http.StatusFound)
		return
	}
	copySessionCookieHeader(r, apiReq)
	apiReq.Header.Set("Content-Type", "application/json")
	apiReq.Header.Set(csrfHeaderName, csrfToken)
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		http.Redirect(w, r, basePath+"?error=Service+unavailable&process=values", http.StatusFound)
		return
	}
	defer apiResp.Body.Close()
	respBody, _ := io.ReadAll(apiResp.Body)
	if apiResp.StatusCode != http.StatusCreated && apiResp.StatusCode != http.StatusOK {
		msg := "unable to create candidate value"
		var errPayload map[string]string
		if err := json.Unmarshal(respBody, &errPayload); err == nil && strings.TrimSpace(errPayload["error"]) != "" {
			msg = errPayload["error"]
		}
		http.Redirect(w, r, basePath+"?error="+url.QueryEscape(msg)+"&process=values", http.StatusFound)
		return
	}
	http.Redirect(w, r, basePath+"?message="+url.QueryEscape("Candidate value created")+"&process=values", http.StatusFound)
}

func (s *server) createCandidateInterviewNameProxy(w http.ResponseWriter, r *http.Request, locationNumber string) {
	basePath := "/admin/locations/" + url.PathEscape(locationNumber) + "/interview-process"
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, basePath+"?error=Invalid+form+submission&process=names", http.StatusFound)
		return
	}
	csrfToken := strings.TrimSpace(r.FormValue("csrf_token"))
	if csrfToken == "" {
		http.Redirect(w, r, basePath+"?error=Missing+csrf+token&process=names", http.StatusFound)
		return
	}
	payload := map[string]string{
		"name": strings.TrimSpace(r.FormValue("name")),
	}
	body, _ := json.Marshal(payload)
	apiReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, s.apiBaseURL+"/api/admin/locations/"+url.PathEscape(locationNumber)+"/candidate-interview-names", bytes.NewReader(body))
	if err != nil {
		http.Redirect(w, r, basePath+"?error=Unable+to+create+interview+name&process=names", http.StatusFound)
		return
	}
	copySessionCookieHeader(r, apiReq)
	apiReq.Header.Set("Content-Type", "application/json")
	apiReq.Header.Set(csrfHeaderName, csrfToken)
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		http.Redirect(w, r, basePath+"?error=Service+unavailable&process=names", http.StatusFound)
		return
	}
	defer apiResp.Body.Close()
	respBody, _ := io.ReadAll(apiResp.Body)
	if apiResp.StatusCode != http.StatusCreated && apiResp.StatusCode != http.StatusOK {
		msg := "unable to create interview type"
		var errPayload map[string]string
		if err := json.Unmarshal(respBody, &errPayload); err == nil && strings.TrimSpace(errPayload["error"]) != "" {
			msg = errPayload["error"]
		}
		http.Redirect(w, r, basePath+"?error="+url.QueryEscape(msg)+"&process=names", http.StatusFound)
		return
	}
	http.Redirect(w, r, basePath+"?message="+url.QueryEscape("Interview type created")+"&process=names", http.StatusFound)
}

func (s *server) createCandidateInterviewQuestionProxy(w http.ResponseWriter, r *http.Request, locationNumber string) {
	basePath := "/admin/locations/" + url.PathEscape(locationNumber) + "/interview-process"
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, basePath+"?error=Invalid+form+submission&process=questions", http.StatusFound)
		return
	}
	csrfToken := strings.TrimSpace(r.FormValue("csrf_token"))
	if csrfToken == "" {
		http.Redirect(w, r, basePath+"?error=Missing+csrf+token&process=questions", http.StatusFound)
		return
	}
	interviewNameIDs := parseInterviewTypeIDs(r.Form["interview_name_ids"])
	interviewNameID, _ := strconv.ParseInt(strings.TrimSpace(r.FormValue("interview_name_id")), 10, 64)
	responseType := strings.ToLower(strings.TrimSpace(r.FormValue("response_type")))
	responseType, responseOptions := normalizeQuestionResponsePayload(responseType, r.Form["response_options"])
	payload := map[string]any{
		"interviewNameId":  interviewNameID,
		"interviewNameIds": interviewNameIDs,
		"question":         strings.TrimSpace(r.FormValue("question")),
		"responseType":     responseType,
		"responseOptions":  responseOptions,
	}
	body, _ := json.Marshal(payload)
	apiReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, s.apiBaseURL+"/api/admin/locations/"+url.PathEscape(locationNumber)+"/candidate-interview-questions", bytes.NewReader(body))
	if err != nil {
		http.Redirect(w, r, basePath+"?error=Unable+to+create+interview+question&process=questions", http.StatusFound)
		return
	}
	copySessionCookieHeader(r, apiReq)
	apiReq.Header.Set("Content-Type", "application/json")
	apiReq.Header.Set(csrfHeaderName, csrfToken)
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		http.Redirect(w, r, basePath+"?error=Service+unavailable&process=questions", http.StatusFound)
		return
	}
	defer apiResp.Body.Close()
	respBody, _ := io.ReadAll(apiResp.Body)
	if apiResp.StatusCode != http.StatusCreated && apiResp.StatusCode != http.StatusOK {
		msg := "unable to create interview question"
		var errPayload map[string]string
		if err := json.Unmarshal(respBody, &errPayload); err == nil && strings.TrimSpace(errPayload["error"]) != "" {
			msg = errPayload["error"]
		}
		http.Redirect(w, r, basePath+"?error="+url.QueryEscape(msg)+"&process=questions", http.StatusFound)
		return
	}
	http.Redirect(w, r, basePath+"?message="+url.QueryEscape("Interview question created")+"&process=questions", http.StatusFound)
}

func (s *server) createCandidateInterviewQuestionStartersProxy(w http.ResponseWriter, r *http.Request, locationNumber string) {
	basePath := "/admin/locations/" + url.PathEscape(locationNumber) + "/interview-process"
	redirectPath := basePath + "?process=questions&question_panel=starter"
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, redirectPath+"&error=Invalid+form+submission", http.StatusFound)
		return
	}
	csrfToken := strings.TrimSpace(r.FormValue("csrf_token"))
	if csrfToken == "" {
		http.Redirect(w, r, redirectPath+"&error=Missing+csrf+token", http.StatusFound)
		return
	}
	interviewNameIDs := parseInterviewTypeIDs(r.Form["interview_name_ids"])
	if len(interviewNameIDs) == 0 {
		http.Redirect(w, r, redirectPath+"&error=Select+at+least+one+interview+type", http.StatusFound)
		return
	}
	selected := uniqueTrimmedValues(r.Form["starter_key"])
	if len(selected) == 0 {
		http.Redirect(w, r, redirectPath+"&error=Select+at+least+one+starter+question", http.StatusFound)
		return
	}

	catalog := interviewQuestionStarterCatalogByKey()
	existingQuestions, err := s.fetchLocationCandidateInterviewQuestions(r, locationNumber)
	if err != nil {
		http.Redirect(w, r, redirectPath+"&error=Unable+to+load+existing+questions", http.StatusFound)
		return
	}
	existingByQuestion := make(map[string]candidateInterviewQuestionView, len(existingQuestions))
	for _, question := range existingQuestions {
		normalized := normalizeStarterQuestionMatch(question.Question)
		if normalized == "" {
			continue
		}
		existingByQuestion[normalized] = question
	}

	added := 0
	updated := 0
	skipped := 0
	for _, key := range selected {
		starter, ok := catalog[key]
		if !ok {
			continue
		}
		normalizedQuestion := normalizeStarterQuestionMatch(starter.Question)
		if normalizedQuestion == "" {
			continue
		}
		if existing, exists := existingByQuestion[normalizedQuestion]; exists {
			mergedInterviewTypeIDs := mergeInterviewTypeIDs(existing.InterviewNameIDs, interviewNameIDs)
			if int64SlicesEqual(existing.InterviewNameIDs, mergedInterviewTypeIDs) {
				skipped++
				continue
			}
			payload := map[string]any{
				"interviewNameIds": mergedInterviewTypeIDs,
			}
			body, _ := json.Marshal(payload)
			apiReq, err := http.NewRequestWithContext(
				r.Context(),
				http.MethodPut,
				s.apiBaseURL+"/api/admin/locations/"+url.PathEscape(locationNumber)+"/candidate-interview-questions/"+strconv.FormatInt(existing.ID, 10),
				bytes.NewReader(body),
			)
			if err != nil {
				http.Redirect(w, r, redirectPath+"&error=Unable+to+update+existing+questions", http.StatusFound)
				return
			}
			copySessionCookieHeader(r, apiReq)
			apiReq.Header.Set("Content-Type", "application/json")
			apiReq.Header.Set(csrfHeaderName, csrfToken)
			apiResp, err := s.apiClient.Do(apiReq)
			if err != nil {
				http.Redirect(w, r, redirectPath+"&error=Service+unavailable", http.StatusFound)
				return
			}
			respBody, _ := io.ReadAll(apiResp.Body)
			apiResp.Body.Close()
			if apiResp.StatusCode != http.StatusOK {
				msg := "unable to update existing interview questions"
				var errPayload map[string]string
				if err := json.Unmarshal(respBody, &errPayload); err == nil && strings.TrimSpace(errPayload["error"]) != "" {
					msg = errPayload["error"]
				}
				http.Redirect(w, r, redirectPath+"&error="+url.QueryEscape(msg), http.StatusFound)
				return
			}
			existing.InterviewNameIDs = mergedInterviewTypeIDs
			existingByQuestion[normalizedQuestion] = existing
			updated++
			continue
		}
		responseType, responseOptions := normalizeQuestionResponsePayload(starter.ResponseType, starter.ResponseOptions)
		payload := map[string]any{
			"interviewNameId":  int64(0),
			"interviewNameIds": interviewNameIDs,
			"question":         starter.Question,
			"responseType":     responseType,
			"responseOptions":  responseOptions,
		}
		body, _ := json.Marshal(payload)
		apiReq, err := http.NewRequestWithContext(
			r.Context(),
			http.MethodPost,
			s.apiBaseURL+"/api/admin/locations/"+url.PathEscape(locationNumber)+"/candidate-interview-questions",
			bytes.NewReader(body),
		)
		if err != nil {
			http.Redirect(w, r, redirectPath+"&error=Unable+to+create+starter+questions", http.StatusFound)
			return
		}
		copySessionCookieHeader(r, apiReq)
		apiReq.Header.Set("Content-Type", "application/json")
		apiReq.Header.Set(csrfHeaderName, csrfToken)
		apiResp, err := s.apiClient.Do(apiReq)
		if err != nil {
			http.Redirect(w, r, redirectPath+"&error=Service+unavailable", http.StatusFound)
			return
		}
		respBody, _ := io.ReadAll(apiResp.Body)
		apiResp.Body.Close()
		if apiResp.StatusCode != http.StatusCreated && apiResp.StatusCode != http.StatusOK {
			msg := "unable to create starter interview questions"
			var errPayload map[string]string
			if err := json.Unmarshal(respBody, &errPayload); err == nil && strings.TrimSpace(errPayload["error"]) != "" {
				msg = errPayload["error"]
			}
			http.Redirect(w, r, redirectPath+"&error="+url.QueryEscape(msg), http.StatusFound)
			return
		}
		existingByQuestion[normalizedQuestion] = candidateInterviewQuestionView{
			Question:         starter.Question,
			InterviewNameIDs: interviewNameIDs,
		}
		added++
	}

	if added == 0 && updated == 0 {
		if skipped > 0 {
			http.Redirect(w, r, redirectPath+"&message="+url.QueryEscape("All selected questions already match the selected interview types"), http.StatusFound)
			return
		}
		http.Redirect(w, r, redirectPath+"&error="+url.QueryEscape("No valid starter questions were selected"), http.StatusFound)
		return
	}
	messageParts := make([]string, 0, 3)
	if added > 0 {
		part := "added " + strconv.Itoa(added) + " question"
		if added != 1 {
			part += "s"
		}
		messageParts = append(messageParts, part)
	}
	if updated > 0 {
		part := "updated " + strconv.Itoa(updated) + " existing question"
		if updated != 1 {
			part += "s"
		}
		messageParts = append(messageParts, part)
	}
	if skipped > 0 {
		part := "skipped " + strconv.Itoa(skipped) + " already assigned"
		messageParts = append(messageParts, part)
	}
	message := strings.Join(messageParts, "; ")
	if message == "" {
		message = "Interview questions updated"
	}
	http.Redirect(w, r, redirectPath+"&message="+url.QueryEscape(message), http.StatusFound)
}

func (s *server) updateCandidateValueProxy(w http.ResponseWriter, r *http.Request, locationNumber string, valueID int64) {
	csrfToken, err := s.fetchCSRFToken(r)
	if err != nil || strings.TrimSpace(csrfToken) == "" {
		http.Error(w, `{"error":"session expired"}`, http.StatusUnauthorized)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}
	apiReq, err := http.NewRequestWithContext(r.Context(), http.MethodPut, s.apiBaseURL+"/api/admin/locations/"+url.PathEscape(locationNumber)+"/candidate-values/"+strconv.FormatInt(valueID, 10), bytes.NewReader(body))
	if err != nil {
		http.Error(w, `{"error":"upstream request failed"}`, http.StatusInternalServerError)
		return
	}
	copySessionCookieHeader(r, apiReq)
	apiReq.Header.Set("Content-Type", "application/json")
	apiReq.Header.Set(csrfHeaderName, csrfToken)
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		http.Error(w, `{"error":"upstream service unavailable"}`, http.StatusBadGateway)
		return
	}
	defer apiResp.Body.Close()
	respBody, _ := io.ReadAll(apiResp.Body)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(apiResp.StatusCode)
	_, _ = w.Write(respBody)
}

func (s *server) deleteCandidateValueProxy(w http.ResponseWriter, r *http.Request, locationNumber string, valueID int64) {
	basePath := "/admin/locations/" + url.PathEscape(locationNumber) + "/interview-process"
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, basePath+"?error=Invalid+form+submission&process=values", http.StatusFound)
		return
	}
	csrfToken := strings.TrimSpace(r.FormValue("csrf_token"))
	if csrfToken == "" {
		http.Redirect(w, r, basePath+"?error=Missing+csrf+token&process=values", http.StatusFound)
		return
	}
	apiReq, err := http.NewRequestWithContext(r.Context(), http.MethodDelete, s.apiBaseURL+"/api/admin/locations/"+url.PathEscape(locationNumber)+"/candidate-values/"+strconv.FormatInt(valueID, 10), nil)
	if err != nil {
		http.Redirect(w, r, basePath+"?error=Unable+to+delete+value&process=values", http.StatusFound)
		return
	}
	copySessionCookieHeader(r, apiReq)
	apiReq.Header.Set(csrfHeaderName, csrfToken)
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		http.Redirect(w, r, basePath+"?error=Service+unavailable&process=values", http.StatusFound)
		return
	}
	defer apiResp.Body.Close()
	respBody, _ := io.ReadAll(apiResp.Body)
	if apiResp.StatusCode != http.StatusOK {
		msg := "unable to delete value"
		var errPayload map[string]string
		if err := json.Unmarshal(respBody, &errPayload); err == nil && strings.TrimSpace(errPayload["error"]) != "" {
			msg = errPayload["error"]
		}
		http.Redirect(w, r, basePath+"?error="+url.QueryEscape(msg)+"&process=values", http.StatusFound)
		return
	}
	http.Redirect(w, r, basePath+"?message="+url.QueryEscape("Candidate value deleted")+"&process=values", http.StatusFound)
}

func (s *server) deleteCandidateInterviewNameProxy(w http.ResponseWriter, r *http.Request, locationNumber string, nameID int64) {
	basePath := "/admin/locations/" + url.PathEscape(locationNumber) + "/interview-process"
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, basePath+"?error=Invalid+form+submission&process=names", http.StatusFound)
		return
	}
	csrfToken := strings.TrimSpace(r.FormValue("csrf_token"))
	if csrfToken == "" {
		http.Redirect(w, r, basePath+"?error=Missing+csrf+token&process=names", http.StatusFound)
		return
	}
	apiReq, err := http.NewRequestWithContext(r.Context(), http.MethodDelete, s.apiBaseURL+"/api/admin/locations/"+url.PathEscape(locationNumber)+"/candidate-interview-names/"+strconv.FormatInt(nameID, 10), nil)
	if err != nil {
		http.Redirect(w, r, basePath+"?error=Unable+to+delete+interview+name&process=names", http.StatusFound)
		return
	}
	copySessionCookieHeader(r, apiReq)
	apiReq.Header.Set(csrfHeaderName, csrfToken)
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		http.Redirect(w, r, basePath+"?error=Service+unavailable&process=names", http.StatusFound)
		return
	}
	defer apiResp.Body.Close()
	respBody, _ := io.ReadAll(apiResp.Body)
	if apiResp.StatusCode != http.StatusOK {
		msg := "unable to delete interview type"
		var errPayload map[string]string
		if err := json.Unmarshal(respBody, &errPayload); err == nil && strings.TrimSpace(errPayload["error"]) != "" {
			msg = errPayload["error"]
		}
		http.Redirect(w, r, basePath+"?error="+url.QueryEscape(msg)+"&process=names", http.StatusFound)
		return
	}
	http.Redirect(w, r, basePath+"?message="+url.QueryEscape("Interview type deleted")+"&process=names", http.StatusFound)
}

func (s *server) updateCandidateInterviewNamePriorityProxy(w http.ResponseWriter, r *http.Request, locationNumber string, nameID int64) {
	basePath := "/admin/locations/" + url.PathEscape(locationNumber) + "/interview-process"
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, basePath+"?error=Invalid+form+submission&process=names", http.StatusFound)
		return
	}
	csrfToken := strings.TrimSpace(r.FormValue("csrf_token"))
	if csrfToken == "" {
		http.Redirect(w, r, basePath+"?error=Missing+csrf+token&process=names", http.StatusFound)
		return
	}
	priority, err := strconv.ParseInt(strings.TrimSpace(r.FormValue("priority")), 10, 64)
	if err != nil {
		http.Redirect(w, r, basePath+"?error=Priority+must+be+a+number&process=names", http.StatusFound)
		return
	}
	body, _ := json.Marshal(map[string]any{"priority": priority})
	apiReq, err := http.NewRequestWithContext(r.Context(), http.MethodPut, s.apiBaseURL+"/api/admin/locations/"+url.PathEscape(locationNumber)+"/candidate-interview-names/"+strconv.FormatInt(nameID, 10), bytes.NewReader(body))
	if err != nil {
		http.Redirect(w, r, basePath+"?error=Unable+to+update+interview+type&process=names", http.StatusFound)
		return
	}
	copySessionCookieHeader(r, apiReq)
	apiReq.Header.Set("Content-Type", "application/json")
	apiReq.Header.Set(csrfHeaderName, csrfToken)
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		http.Redirect(w, r, basePath+"?error=Service+unavailable&process=names", http.StatusFound)
		return
	}
	defer apiResp.Body.Close()
	respBody, _ := io.ReadAll(apiResp.Body)
	if apiResp.StatusCode != http.StatusOK {
		msg := "unable to update interview type"
		var errPayload map[string]string
		if err := json.Unmarshal(respBody, &errPayload); err == nil && strings.TrimSpace(errPayload["error"]) != "" {
			msg = errPayload["error"]
		}
		http.Redirect(w, r, basePath+"?error="+url.QueryEscape(msg)+"&process=names", http.StatusFound)
		return
	}
	http.Redirect(w, r, basePath+"?message="+url.QueryEscape("Interview type priority updated")+"&process=names", http.StatusFound)
}

func (s *server) reorderCandidateInterviewNamesProxy(w http.ResponseWriter, r *http.Request, locationNumber string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	csrfToken, err := s.fetchCSRFToken(r)
	if err != nil || strings.TrimSpace(csrfToken) == "" {
		http.Error(w, `{"error":"session expired"}`, http.StatusUnauthorized)
		return
	}
	var req struct {
		OrderedIDs []int64 `json:"orderedIds"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}
	if len(req.OrderedIDs) == 0 {
		http.Error(w, `{"error":"orderedIds is required"}`, http.StatusBadRequest)
		return
	}
	seen := make(map[int64]struct{}, len(req.OrderedIDs))
	for _, id := range req.OrderedIDs {
		if id <= 0 {
			http.Error(w, `{"error":"orderedIds must contain valid ids"}`, http.StatusBadRequest)
			return
		}
		if _, exists := seen[id]; exists {
			http.Error(w, `{"error":"orderedIds must be unique"}`, http.StatusBadRequest)
			return
		}
		seen[id] = struct{}{}
	}
	for idx, id := range req.OrderedIDs {
		payloadBody, _ := json.Marshal(map[string]any{"priority": idx + 1})
		apiReq, err := http.NewRequestWithContext(
			r.Context(),
			http.MethodPut,
			s.apiBaseURL+"/api/admin/locations/"+url.PathEscape(locationNumber)+"/candidate-interview-names/"+strconv.FormatInt(id, 10),
			bytes.NewReader(payloadBody),
		)
		if err != nil {
			http.Error(w, `{"error":"upstream request failed"}`, http.StatusInternalServerError)
			return
		}
		copySessionCookieHeader(r, apiReq)
		apiReq.Header.Set("Content-Type", "application/json")
		apiReq.Header.Set(csrfHeaderName, csrfToken)
		apiResp, err := s.apiClient.Do(apiReq)
		if err != nil {
			http.Error(w, `{"error":"upstream service unavailable"}`, http.StatusBadGateway)
			return
		}
		respBody, _ := io.ReadAll(apiResp.Body)
		apiResp.Body.Close()
		if apiResp.StatusCode != http.StatusOK {
			msg := "unable to update interview type order"
			var errPayload map[string]string
			if err := json.Unmarshal(respBody, &errPayload); err == nil && strings.TrimSpace(errPayload["error"]) != "" {
				msg = errPayload["error"]
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(apiResp.StatusCode)
			_, _ = w.Write([]byte(`{"error":` + strconv.Quote(msg) + `}`))
			return
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"message":"Interview type order updated"}`))
}

func (s *server) deleteCandidateInterviewQuestionProxy(w http.ResponseWriter, r *http.Request, locationNumber string, questionID int64) {
	basePath := "/admin/locations/" + url.PathEscape(locationNumber) + "/interview-process"
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, basePath+"?error=Invalid+form+submission&process=questions", http.StatusFound)
		return
	}
	csrfToken := strings.TrimSpace(r.FormValue("csrf_token"))
	if csrfToken == "" {
		http.Redirect(w, r, basePath+"?error=Missing+csrf+token&process=questions", http.StatusFound)
		return
	}
	apiReq, err := http.NewRequestWithContext(r.Context(), http.MethodDelete, s.apiBaseURL+"/api/admin/locations/"+url.PathEscape(locationNumber)+"/candidate-interview-questions/"+strconv.FormatInt(questionID, 10), nil)
	if err != nil {
		http.Redirect(w, r, basePath+"?error=Unable+to+delete+interview+question&process=questions", http.StatusFound)
		return
	}
	copySessionCookieHeader(r, apiReq)
	apiReq.Header.Set(csrfHeaderName, csrfToken)
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		http.Redirect(w, r, basePath+"?error=Service+unavailable&process=questions", http.StatusFound)
		return
	}
	defer apiResp.Body.Close()
	respBody, _ := io.ReadAll(apiResp.Body)
	if apiResp.StatusCode != http.StatusOK {
		msg := "unable to delete interview question"
		var errPayload map[string]string
		if err := json.Unmarshal(respBody, &errPayload); err == nil && strings.TrimSpace(errPayload["error"]) != "" {
			msg = errPayload["error"]
		}
		http.Redirect(w, r, basePath+"?error="+url.QueryEscape(msg)+"&process=questions", http.StatusFound)
		return
	}
	http.Redirect(w, r, basePath+"?message="+url.QueryEscape("Interview question deleted")+"&process=questions", http.StatusFound)
}

func (s *server) assignCandidateInterviewQuestionProxy(w http.ResponseWriter, r *http.Request, locationNumber string, questionID int64) {
	basePath := "/admin/locations/" + url.PathEscape(locationNumber) + "/interview-process"
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, basePath+"?error=Invalid+form+submission&process=questions", http.StatusFound)
		return
	}
	csrfToken := strings.TrimSpace(r.FormValue("csrf_token"))
	if csrfToken == "" {
		http.Redirect(w, r, basePath+"?error=Missing+csrf+token&process=questions", http.StatusFound)
		return
	}
	interviewNameIDs := parseInterviewTypeIDs(r.Form["interview_name_ids"])
	interviewNameID, _ := strconv.ParseInt(strings.TrimSpace(r.FormValue("interview_name_id")), 10, 64)
	responseType := strings.ToLower(strings.TrimSpace(r.FormValue("response_type")))
	responseType, responseOptions := normalizeQuestionResponsePayload(responseType, r.Form["response_options"])
	payload := map[string]any{
		"interviewNameId":  interviewNameID,
		"interviewNameIds": interviewNameIDs,
		"responseType":     responseType,
		"responseOptions":  responseOptions,
	}
	question := strings.TrimSpace(r.FormValue("question"))
	if question != "" {
		payload["question"] = question
	}
	body, _ := json.Marshal(payload)
	apiReq, err := http.NewRequestWithContext(r.Context(), http.MethodPut, s.apiBaseURL+"/api/admin/locations/"+url.PathEscape(locationNumber)+"/candidate-interview-questions/"+strconv.FormatInt(questionID, 10), bytes.NewReader(body))
	if err != nil {
		http.Redirect(w, r, basePath+"?error=Unable+to+assign+interview+type&process=questions", http.StatusFound)
		return
	}
	copySessionCookieHeader(r, apiReq)
	apiReq.Header.Set("Content-Type", "application/json")
	apiReq.Header.Set(csrfHeaderName, csrfToken)
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		http.Redirect(w, r, basePath+"?error=Service+unavailable&process=questions", http.StatusFound)
		return
	}
	defer apiResp.Body.Close()
	respBody, _ := io.ReadAll(apiResp.Body)
	if apiResp.StatusCode != http.StatusOK {
		msg := "unable to update interview question"
		var errPayload map[string]string
		if err := json.Unmarshal(respBody, &errPayload); err == nil && strings.TrimSpace(errPayload["error"]) != "" {
			msg = errPayload["error"]
		}
		http.Redirect(w, r, basePath+"?error="+url.QueryEscape(msg)+"&process=questions", http.StatusFound)
		return
	}
	http.Redirect(w, r, basePath+"?message="+url.QueryEscape("Interview question updated")+"&process=questions", http.StatusFound)
}

func (s *server) createCandidateInterviewProxy(w http.ResponseWriter, r *http.Request, locationNumber string, candidateID int64) {
	http.Redirect(
		w,
		r,
		"/admin/locations/"+url.PathEscape(locationNumber)+"/candidates/"+strconv.FormatInt(candidateID, 10)+"?error="+url.QueryEscape("Interviews can only be completed through generated links")+"#view-interviews",
		http.StatusFound,
	)
}

func (s *server) createCandidateInterviewLinkProxy(w http.ResponseWriter, r *http.Request, locationNumber string, candidateID int64) {
	csrfToken := strings.TrimSpace(r.Header.Get(csrfHeaderName))
	if csrfToken == "" {
		http.Error(w, `{"error":"csrf token is required"}`, http.StatusForbidden)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}
	apiReq, err := http.NewRequestWithContext(
		r.Context(),
		http.MethodPost,
		s.apiBaseURL+"/api/admin/locations/"+url.PathEscape(locationNumber)+"/candidates/"+strconv.FormatInt(candidateID, 10)+"/interview-link",
		bytes.NewReader(body),
	)
	if err != nil {
		http.Error(w, `{"error":"upstream request failed"}`, http.StatusInternalServerError)
		return
	}
	copySessionCookieHeader(r, apiReq)
	apiReq.Header.Set("Content-Type", "application/json")
	apiReq.Header.Set(csrfHeaderName, csrfToken)
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		http.Error(w, `{"error":"upstream service unavailable"}`, http.StatusBadGateway)
		return
	}
	defer apiResp.Body.Close()
	respBody, _ := io.ReadAll(apiResp.Body)
	if apiResp.StatusCode != http.StatusCreated && apiResp.StatusCode != http.StatusOK {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(apiResp.StatusCode)
		_, _ = w.Write(respBody)
		return
	}
	var payload interviewLinkResponse
	if err := json.Unmarshal(respBody, &payload); err != nil || strings.TrimSpace(payload.Token) == "" {
		http.Error(w, `{"error":"invalid upstream response"}`, http.StatusBadGateway)
		return
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	link := scheme + "://" + r.Host + "/interview/" + url.PathEscape(payload.Token)
	writeJSON(w, http.StatusOK, map[string]string{
		"link":      link,
		"expiresAt": payload.ExpiresAt,
	})
}

func (s *server) createCandidateInterviewSessionProxy(w http.ResponseWriter, r *http.Request, locationNumber string, candidateID int64) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/candidates/"+strconv.FormatInt(candidateID, 10)+"?error=Invalid+form+submission#view-interviews", http.StatusFound)
		return
	}
	csrfToken := strings.TrimSpace(r.FormValue("csrf_token"))
	if csrfToken == "" {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/candidates/"+strconv.FormatInt(candidateID, 10)+"?error=Missing+csrf+token#view-interviews", http.StatusFound)
		return
	}
	scheduledAt := strings.TrimSpace(r.FormValue("scheduled_at"))
	if scheduledAt == "" {
		scheduledDate := strings.TrimSpace(r.FormValue("scheduled_date"))
		scheduledHour := strings.TrimSpace(r.FormValue("scheduled_hour"))
		scheduledMinute := strings.TrimSpace(r.FormValue("scheduled_minute"))
		scheduledAMPM := strings.ToUpper(strings.TrimSpace(r.FormValue("scheduled_ampm")))
		if scheduledDate == "" || scheduledHour == "" || scheduledMinute == "" || (scheduledAMPM != "AM" && scheduledAMPM != "PM") {
			http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/candidates/"+strconv.FormatInt(candidateID, 10)+"?error="+url.QueryEscape("Interview date and time are required")+"#view-interviews", http.StatusFound)
			return
		}
		hourNum, err := strconv.Atoi(scheduledHour)
		if err != nil || hourNum < 1 || hourNum > 12 {
			http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/candidates/"+strconv.FormatInt(candidateID, 10)+"?error="+url.QueryEscape("Interview hour is invalid")+"#view-interviews", http.StatusFound)
			return
		}
		minuteNum, err := strconv.Atoi(scheduledMinute)
		if err != nil || minuteNum < 0 || minuteNum > 59 {
			http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/candidates/"+strconv.FormatInt(candidateID, 10)+"?error="+url.QueryEscape("Interview minute is invalid")+"#view-interviews", http.StatusFound)
			return
		}
		hour24 := hourNum % 12
		if scheduledAMPM == "PM" {
			hour24 += 12
		}
		scheduledAt = fmt.Sprintf("%s %02d:%02d", scheduledDate, hour24, minuteNum)
	}
	body, _ := json.Marshal(map[string]string{
		"interviewerTimePunchName": strings.TrimSpace(r.FormValue("interviewer_time_punch_name")),
		"interviewType":            strings.TrimSpace(r.FormValue("interview_type")),
		"scheduledAt":              scheduledAt,
	})
	apiReq, err := http.NewRequestWithContext(
		r.Context(),
		http.MethodPost,
		s.apiBaseURL+"/api/admin/locations/"+url.PathEscape(locationNumber)+"/candidates/"+strconv.FormatInt(candidateID, 10)+"/interview-link",
		bytes.NewReader(body),
	)
	if err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/candidates/"+strconv.FormatInt(candidateID, 10)+"?error=Unable+to+create+interview#view-interviews", http.StatusFound)
		return
	}
	copySessionCookieHeader(r, apiReq)
	apiReq.Header.Set("Content-Type", "application/json")
	apiReq.Header.Set(csrfHeaderName, csrfToken)
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/candidates/"+strconv.FormatInt(candidateID, 10)+"?error=Service+unavailable#view-interviews", http.StatusFound)
		return
	}
	defer apiResp.Body.Close()
	respBody, _ := io.ReadAll(apiResp.Body)
	if apiResp.StatusCode != http.StatusCreated && apiResp.StatusCode != http.StatusOK {
		msg := "unable to create interview"
		var errPayload map[string]string
		if err := json.Unmarshal(respBody, &errPayload); err == nil && strings.TrimSpace(errPayload["error"]) != "" {
			msg = errPayload["error"]
		}
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/candidates/"+strconv.FormatInt(candidateID, 10)+"?error="+url.QueryEscape(msg)+"#view-interviews", http.StatusFound)
		return
	}
	var payload interviewLinkResponse
	if err := json.Unmarshal(respBody, &payload); err != nil || strings.TrimSpace(payload.Token) == "" {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/candidates/"+strconv.FormatInt(candidateID, 10)+"?error=Unable+to+read+interview+link#view-interviews", http.StatusFound)
		return
	}
	http.Redirect(
		w,
		r,
		"/admin/locations/"+url.PathEscape(locationNumber)+"/candidates/"+strconv.FormatInt(candidateID, 10)+"?open_session="+url.QueryEscape(payload.Token)+"#view-interviews",
		http.StatusFound,
	)
}

func (s *server) deleteCandidateInterviewLinkProxy(w http.ResponseWriter, r *http.Request, locationNumber string, candidateID int64, token string) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/candidates/"+strconv.FormatInt(candidateID, 10)+"?error=Invalid+form+submission#view-interviews", http.StatusFound)
		return
	}
	csrfToken := strings.TrimSpace(r.FormValue("csrf_token"))
	if csrfToken == "" {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/candidates/"+strconv.FormatInt(candidateID, 10)+"?error=Missing+csrf+token#view-interviews", http.StatusFound)
		return
	}
	apiReq, err := http.NewRequestWithContext(
		r.Context(),
		http.MethodDelete,
		s.apiBaseURL+"/api/admin/locations/"+url.PathEscape(locationNumber)+"/candidates/"+strconv.FormatInt(candidateID, 10)+"/interview-links/"+url.PathEscape(token),
		nil,
	)
	if err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/candidates/"+strconv.FormatInt(candidateID, 10)+"?error=Unable+to+delete+interview#view-interviews", http.StatusFound)
		return
	}
	copySessionCookieHeader(r, apiReq)
	apiReq.Header.Set(csrfHeaderName, csrfToken)
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/candidates/"+strconv.FormatInt(candidateID, 10)+"?error=Service+unavailable#view-interviews", http.StatusFound)
		return
	}
	defer apiResp.Body.Close()
	respBody, _ := io.ReadAll(apiResp.Body)
	if apiResp.StatusCode != http.StatusOK {
		msg := "unable to delete interview"
		var errPayload map[string]string
		if err := json.Unmarshal(respBody, &errPayload); err == nil && strings.TrimSpace(errPayload["error"]) != "" {
			msg = errPayload["error"]
		}
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/candidates/"+strconv.FormatInt(candidateID, 10)+"?error="+url.QueryEscape(msg)+"#view-interviews", http.StatusFound)
		return
	}
	http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/candidates/"+strconv.FormatInt(candidateID, 10)+"?message="+url.QueryEscape("Interview deleted")+"#view-interviews", http.StatusFound)
}

func (s *server) updateCandidateDecisionProxy(w http.ResponseWriter, r *http.Request, locationNumber string, candidateID int64) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/candidates?error=Invalid+form+submission", http.StatusFound)
		return
	}
	csrfToken := strings.TrimSpace(r.FormValue("csrf_token"))
	if csrfToken == "" {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/candidates?error=Missing+csrf+token", http.StatusFound)
		return
	}
	payBandID := parsePositiveInt(strings.TrimSpace(r.FormValue("pay_band_id")), 0)
	if payBandID <= 0 {
		payBandID = parsePositiveInt(strings.TrimSpace(r.FormValue("job_id")), 0)
	}
	departmentID := parsePositiveInt(strings.TrimSpace(r.FormValue("department_id")), 0)
	payload := map[string]any{
		"decision": strings.TrimSpace(r.FormValue("decision")),
	}
	if departmentID > 0 {
		payload["departmentId"] = departmentID
	}
	if payBandID > 0 {
		payload["payBandId"] = payBandID
	}
	body, _ := json.Marshal(payload)
	apiReq, err := http.NewRequestWithContext(r.Context(), http.MethodPut, s.apiBaseURL+"/api/admin/locations/"+url.PathEscape(locationNumber)+"/candidates/"+strconv.FormatInt(candidateID, 10), bytes.NewReader(body))
	if err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/candidates?error=Unable+to+update+candidate", http.StatusFound)
		return
	}
	copySessionCookieHeader(r, apiReq)
	apiReq.Header.Set("Content-Type", "application/json")
	apiReq.Header.Set(csrfHeaderName, csrfToken)
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/candidates?error=Service+unavailable", http.StatusFound)
		return
	}
	defer apiResp.Body.Close()
	respBody, _ := io.ReadAll(apiResp.Body)
	if apiResp.StatusCode != http.StatusOK {
		msg := "unable to update candidate"
		var errPayload map[string]string
		if err := json.Unmarshal(respBody, &errPayload); err == nil && strings.TrimSpace(errPayload["error"]) != "" {
			msg = errPayload["error"]
		}
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/candidates?error="+url.QueryEscape(msg), http.StatusFound)
		return
	}
	http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/candidates?message="+url.QueryEscape("Candidate decision saved"), http.StatusFound)
}

func (s *server) deleteCandidateProxy(w http.ResponseWriter, r *http.Request, locationNumber string, candidateID int64) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/candidates?error=Invalid+form+submission", http.StatusFound)
		return
	}
	csrfToken := strings.TrimSpace(r.FormValue("csrf_token"))
	if csrfToken == "" {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/candidates?error=Missing+csrf+token", http.StatusFound)
		return
	}
	apiReq, err := http.NewRequestWithContext(
		r.Context(),
		http.MethodDelete,
		s.apiBaseURL+"/api/admin/locations/"+url.PathEscape(locationNumber)+"/candidates/"+strconv.FormatInt(candidateID, 10),
		nil,
	)
	if err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/candidates?error=Unable+to+delete+candidate", http.StatusFound)
		return
	}
	copySessionCookieHeader(r, apiReq)
	apiReq.Header.Set(csrfHeaderName, csrfToken)
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/candidates?error=Service+unavailable", http.StatusFound)
		return
	}
	defer apiResp.Body.Close()
	respBody, _ := io.ReadAll(apiResp.Body)
	if apiResp.StatusCode != http.StatusOK {
		msg := "unable to delete candidate"
		var errPayload map[string]string
		if err := json.Unmarshal(respBody, &errPayload); err == nil && strings.TrimSpace(errPayload["error"]) != "" {
			msg = errPayload["error"]
		}
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/candidates?error="+url.QueryEscape(msg), http.StatusFound)
		return
	}
	http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/candidates?message="+url.QueryEscape("Candidate deleted"), http.StatusFound)
}

func (s *server) publicPhotoUploadRoutes(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.URL.Path, "/employee/photo-upload/")
	token = strings.TrimSpace(strings.Trim(token, "/"))
	if token == "" {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodGet:
		s.publicPhotoUploadPage(w, r, token)
	case http.MethodPost:
		s.publicPhotoUploadSubmit(w, r, token)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *server) publicEmployeePaperworkRoutes(w http.ResponseWriter, r *http.Request) {
	pathTail := strings.TrimPrefix(r.URL.Path, "/employee/paperwork/")
	pathTail = strings.TrimSpace(strings.Trim(pathTail, "/"))
	if pathTail == "" {
		http.NotFound(w, r)
		return
	}
	segments := strings.Split(pathTail, "/")
	for _, segment := range segments {
		if strings.EqualFold(strings.TrimSpace(segment), "packets") {
			s.publicEmployeePaperworkPacketProxy(w, r, pathTail)
			return
		}
	}
	switch r.Method {
	case http.MethodGet:
		s.publicEmployeePaperworkPage(w, r, pathTail)
	case http.MethodPost:
		s.publicEmployeePaperworkSubmit(w, r, pathTail)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *server) publicEmployeePaperworkPacketProxy(w http.ResponseWriter, r *http.Request, pathTail string) {
	apiURL := s.apiBaseURL + "/api/public/employee-paperwork/" + encodePathTail(pathTail)
	isPacketDocumentFile := strings.Contains(pathTail, "/documents/") && strings.HasSuffix(pathTail, "/file")
	var body io.Reader
	if r.Body != nil {
		body = r.Body
	}
	apiReq, err := http.NewRequestWithContext(r.Context(), r.Method, apiURL, body)
	if err != nil {
		http.Error(w, "request failed", http.StatusInternalServerError)
		return
	}
	if ct := strings.TrimSpace(r.Header.Get("Content-Type")); ct != "" {
		apiReq.Header.Set("Content-Type", ct)
	}
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		http.Error(w, "service unavailable", http.StatusBadGateway)
		return
	}
	defer apiResp.Body.Close()
	if ct := strings.TrimSpace(apiResp.Header.Get("Content-Type")); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	if isPacketDocumentFile {
		// Allow same-origin embedding for the in-page packet signing PDF frame.
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		w.Header().Set("Content-Security-Policy", "frame-ancestors 'self'")
	}
	w.WriteHeader(apiResp.StatusCode)
	_, _ = io.Copy(w, apiResp.Body)
}

func (s *server) publicInterviewRoutes(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.URL.Path, "/interview/")
	token = strings.TrimSpace(strings.Trim(token, "/"))
	if token == "" {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodGet:
		s.publicInterviewPage(w, r, token)
	case http.MethodPost:
		s.publicInterviewSubmit(w, r, token)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *server) publicTimePunchRoutes(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.URL.Path, "/time-punch/")
	token = strings.TrimSpace(strings.Trim(token, "/"))
	if token == "" {
		http.NotFound(w, r)
		return
	}
	s.redirectLegacyTeamFormToPortal(w, r, token)
}

func (s *server) publicTimeOffRoutes(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.URL.Path, "/time-off/")
	token = strings.TrimSpace(strings.Trim(token, "/"))
	if token == "" {
		http.NotFound(w, r)
		return
	}
	s.redirectLegacyTeamFormToPortal(w, r, token)
}

func (s *server) publicUniformOrderRoutes(w http.ResponseWriter, r *http.Request) {
	trimmed := strings.Trim(strings.TrimPrefix(r.URL.Path, "/uniform-order/"), "/")
	if trimmed == "" {
		http.NotFound(w, r)
		return
	}
	parts := strings.Split(trimmed, "/")
	token := strings.TrimSpace(parts[0])
	if token == "" {
		http.NotFound(w, r)
		return
	}

	if len(parts) == 1 {
		s.redirectLegacyTeamFormToPortal(w, r, token)
		return
	}

	if len(parts) == 3 && parts[1] == "item" {
		s.redirectLegacyTeamFormToPortal(w, r, token)
		return
	}

	http.NotFound(w, r)
}

func (s *server) redirectLegacyTeamFormToPortal(w http.ResponseWriter, r *http.Request, token string) {
	target := "/team-login/" + url.PathEscape(token) + "?message=" + url.QueryEscape("Sign in to access team apps.")
	http.Redirect(w, r, target, http.StatusFound)
}

func (s *server) employeeDetailPage(w http.ResponseWriter, r *http.Request, locationNumber, timePunchName string) {
	location, err := s.fetchLocation(r, locationNumber)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	csrfToken, err := s.fetchCSRFToken(r)
	if err != nil {
		http.Redirect(w, r, "/?error=Session+expired", http.StatusFound)
		return
	}
	employee, err := s.fetchEmployee(r, locationNumber, timePunchName)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	i9, docs, i9History, err := s.fetchEmployeePaperwork(r, locationNumber, timePunchName, false, "i9")
	if err != nil {
		http.Error(w, "unable to load employee i9 records", http.StatusBadGateway)
		return
	}
	w4, _, w4History, err := s.fetchEmployeePaperwork(r, locationNumber, timePunchName, false, "w4")
	if err != nil {
		http.Error(w, "unable to load employee w4 records", http.StatusBadGateway)
		return
	}
	jobs, err := s.fetchLocationJobs(r, locationNumber)
	if err != nil {
		http.Error(w, "unable to load location jobs", http.StatusBadGateway)
		return
	}
	departments, err := s.fetchLocationDepartments(r, locationNumber)
	if err != nil {
		http.Error(w, "unable to load location departments", http.StatusBadGateway)
		return
	}
	scorecards, err := s.fetchEmployeeCandidateScorecards(r, locationNumber, timePunchName)
	if err != nil {
		http.Error(w, "unable to load employee scorecards", http.StatusBadGateway)
		return
	}
	additionalCompensations, err := s.fetchEmployeeAdditionalCompensations(r, locationNumber, timePunchName)
	if err != nil {
		http.Error(w, "unable to load additional compensations", http.StatusBadGateway)
		return
	}
	paperworkSections := []paperworkSectionView{
		{Type: "i9", Label: "I-9", HasDocuments: true, Form: i9, Documents: docs},
		{Type: "w4", Label: "W-4", HasDocuments: false, Form: w4, Documents: nil},
	}
	manualPaperworkMissing := manualPaperworkRequiredFieldsForUpload(employee)
	missingProfileFieldSet := make(map[string]bool, len(manualPaperworkMissing))
	for _, field := range manualPaperworkMissing {
		missingProfileFieldSet[field] = true
	}
	birthMonth, birthDay, birthYear := splitBirthdayInput(employee.Birthday)

	if err := renderHTMLTemplate(w, s.employeeTmpl, pageData{
		CSRF:                            csrfToken,
		Location:                        location,
		Employee:                        employee,
		EmployeePayAmountInput:          formatPayAmountInput(employee.PayAmountCents),
		EmployeeBirthMonthInput:         birthMonth,
		EmployeeBirthDayInput:           birthDay,
		EmployeeBirthYearInput:          birthYear,
		EmployeePaperworkLink:           employeePaperworkLink(r, locationNumber, timePunchName),
		LocationJobs:                    jobs,
		LocationDepartments:             departments,
		EmployeeI9:                      i9,
		EmployeeI9Documents:             docs,
		EmployeeI9History:               i9History,
		EmployeeW4:                      w4,
		EmployeeW4History:               w4History,
		EmployeeScorecards:              scorecards,
		EmployeeAdditionalCompensations: additionalCompensations,
		PaperworkSections:               paperworkSections,
		CanManualPaperworkUpload:        len(manualPaperworkMissing) == 0,
		ManualPaperworkUploadMissing:    manualPaperworkMissing,
		EmployeeMissingProfileFields:    manualPaperworkMissing,
		EmployeeMissingProfileFieldSet:  missingProfileFieldSet,
		HasEmployeeMissingProfileFields: len(manualPaperworkMissing) > 0,
		IsArchivedEmployee:              false,
		IsNewHireEmployee:               !employee.HasCompletedPaperwork,
		IsActiveEmployee:                employee.HasCompletedPaperwork,
		SuccessMessage:                  r.URL.Query().Get("message"),
		Error:                           r.URL.Query().Get("error"),
	}); err != nil {
		http.Error(w, "template render failed", http.StatusInternalServerError)
		log.Printf("employee template render failed: %v", err)
	}
}

func (s *server) archivedLocationEmployeesPage(w http.ResponseWriter, r *http.Request, locationNumber string) {
	location, err := s.fetchLocation(r, locationNumber)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	csrfToken, err := s.fetchCSRFToken(r)
	if err != nil {
		http.Redirect(w, r, "/?error=Session+expired", http.StatusFound)
		return
	}
	employees, err := s.fetchArchivedLocationEmployees(r, locationNumber)
	if err != nil {
		http.Error(w, "unable to load archived employees", http.StatusBadGateway)
		return
	}
	if err := renderHTMLTemplate(w, s.archivedEmployeesTmpl, pageData{
		Location:          location,
		CSRF:              csrfToken,
		ArchivedEmployees: employees,
		SuccessMessage:    r.URL.Query().Get("message"),
		Error:             r.URL.Query().Get("error"),
	}); err != nil {
		http.Error(w, "template render failed", http.StatusInternalServerError)
		log.Printf("archived employees template render failed: %v", err)
	}
}

func (s *server) archivedEmployeeDetailPage(w http.ResponseWriter, r *http.Request, locationNumber, timePunchName string) {
	location, err := s.fetchLocation(r, locationNumber)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	csrfToken, err := s.fetchCSRFToken(r)
	if err != nil {
		http.Redirect(w, r, "/?error=Session+expired", http.StatusFound)
		return
	}
	employee, err := s.fetchArchivedEmployee(r, locationNumber, timePunchName)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	i9, docs, i9History, err := s.fetchEmployeePaperwork(r, locationNumber, timePunchName, true, "i9")
	if err != nil {
		http.Error(w, "unable to load archived employee i9 records", http.StatusBadGateway)
		return
	}
	w4, _, w4History, err := s.fetchEmployeePaperwork(r, locationNumber, timePunchName, true, "w4")
	if err != nil {
		http.Error(w, "unable to load archived employee w4 records", http.StatusBadGateway)
		return
	}
	scorecards, err := s.fetchEmployeeCandidateScorecards(r, locationNumber, timePunchName)
	if err != nil {
		http.Error(w, "unable to load employee scorecards", http.StatusBadGateway)
		return
	}
	paperworkSections := []paperworkSectionView{
		{Type: "i9", Label: "I-9", HasDocuments: true, Form: i9, Documents: docs},
		{Type: "w4", Label: "W-4", HasDocuments: false, Form: w4, Documents: nil},
	}
	birthMonth, birthDay, birthYear := splitBirthdayInput(employee.Birthday)
	if err := renderHTMLTemplate(w, s.employeeTmpl, pageData{
		CSRF:                    csrfToken,
		Location:                location,
		Employee:                employee,
		EmployeePayAmountInput:  formatPayAmountInput(employee.PayAmountCents),
		EmployeeBirthMonthInput: birthMonth,
		EmployeeBirthDayInput:   birthDay,
		EmployeeBirthYearInput:  birthYear,
		EmployeeI9:              i9,
		EmployeeI9Documents:     docs,
		EmployeeI9History:       i9History,
		EmployeeW4:              w4,
		EmployeeW4History:       w4History,
		EmployeeScorecards:      scorecards,
		PaperworkSections:       paperworkSections,
		IsArchivedEmployee:      true,
		IsNewHireEmployee:       false,
		IsActiveEmployee:        false,
		SuccessMessage:          r.URL.Query().Get("message"),
		Error:                   r.URL.Query().Get("error"),
	}); err != nil {
		http.Error(w, "template render failed", http.StatusInternalServerError)
		log.Printf("archived employee template render failed: %v", err)
	}
}

func (s *server) publicInterviewPage(w http.ResponseWriter, r *http.Request, token string) {
	apiURL := s.apiBaseURL + "/api/public/interview/" + url.PathEscape(token)
	apiReq, err := http.NewRequestWithContext(r.Context(), http.MethodGet, apiURL, nil)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		http.Error(w, "interview service unavailable", http.StatusBadGateway)
		return
	}
	defer apiResp.Body.Close()
	if apiResp.StatusCode == http.StatusNotFound || apiResp.StatusCode == http.StatusGone {
		s.renderPublicInterviewClosedPage(w, r)
		return
	}
	if apiResp.StatusCode != http.StatusOK {
		http.Error(w, "unable to load interview", http.StatusBadGateway)
		return
	}
	var payload publicInterviewResponse
	if err := json.NewDecoder(apiResp.Body).Decode(&payload); err != nil {
		http.Error(w, "invalid interview response", http.StatusBadGateway)
		return
	}
	location := &locationView{
		Number: payload.LocationNumber,
		Name:   payload.LocationName,
	}
	candidate := &candidateView{
		ID:             payload.CandidateID,
		LocationNumber: payload.LocationNumber,
		FirstName:      payload.CandidateFirstName,
		LastName:       payload.CandidateLastName,
	}
	if err := renderHTMLTemplate(w, s.publicInterviewTmpl, pageData{
		Token:              token,
		Location:           location,
		Candidate:          candidate,
		CandidateValues:    payload.Values,
		InterviewQuestions: payload.Questions,
		Employee:           &employeeView{TimePunchName: payload.InterviewerTimePunchName},
		ReturnPath:         payload.InterviewType,
		SuccessMessage:     r.URL.Query().Get("message"),
		Error:              r.URL.Query().Get("error"),
	}); err != nil {
		http.Error(w, "template render failed", http.StatusInternalServerError)
		log.Printf("public interview template render failed: %v", err)
	}
}

func (s *server) publicInterviewSubmit(w http.ResponseWriter, r *http.Request, token string) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/interview/"+url.PathEscape(token)+"?error=Invalid+form+submission", http.StatusFound)
		return
	}
	form := url.Values{}
	for key, values := range r.PostForm {
		for _, v := range values {
			form.Add(key, v)
		}
	}
	apiReq, err := http.NewRequestWithContext(
		r.Context(),
		http.MethodPost,
		s.apiBaseURL+"/api/public/interview/"+url.PathEscape(token),
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		http.Redirect(w, r, "/interview/"+url.PathEscape(token)+"?error=Unable+to+submit+interview", http.StatusFound)
		return
	}
	apiReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		http.Redirect(w, r, "/interview/"+url.PathEscape(token)+"?error=Service+unavailable", http.StatusFound)
		return
	}
	defer apiResp.Body.Close()
	respBody, _ := io.ReadAll(apiResp.Body)
	if apiResp.StatusCode != http.StatusOK {
		msg := "unable to submit interview"
		var errPayload map[string]string
		if err := json.Unmarshal(respBody, &errPayload); err == nil && strings.TrimSpace(errPayload["error"]) != "" {
			msg = errPayload["error"]
		}
		http.Redirect(w, r, "/interview/"+url.PathEscape(token)+"?error="+url.QueryEscape(msg), http.StatusFound)
		return
	}
	http.Redirect(w, r, "/interview/"+url.PathEscape(token)+"?submitted=1", http.StatusFound)
}

func (s *server) renderPublicInterviewClosedPage(w http.ResponseWriter, r *http.Request) {
	submitted := strings.TrimSpace(r.URL.Query().Get("submitted")) == "1"
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusGone)
	if submitted {
		_, _ = io.WriteString(w, `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Interview Submitted</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Manrope:wght@500;600;700;800&family=Space+Grotesk:wght@500;700&display=swap" rel="stylesheet">
<script>
(function () {
  var stored = localStorage.getItem("cfasuite-theme");
  var prefersDark = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
  var theme = stored === "light" || stored === "dark" ? stored : (prefersDark ? "dark" : "light");
  document.documentElement.classList.toggle("dark", theme === "dark");
})();
</script>
<style>
:root{--bg:#fff;--fg:#09090b;--card:#fff;--muted:#71717a;--border:#e4e4e7}
html.dark{--bg:#09090b;--fg:#fafafa;--card:#09090b;--muted:#a1a1aa;--border:#3f3f46}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font-family:"Manrope",sans-serif}
.wrap{max-width:760px;margin:0 auto;padding:4rem 1rem}
.card{border:1px solid var(--border);border-radius:12px;background:var(--card);padding:1rem}
h1{margin:0 0 .6rem;font-size:1.35rem;font-family:"Space Grotesk",sans-serif}
p{margin:0 0 .5rem;color:var(--muted);line-height:1.45}
</style>
</head>
<body>
  <div class="wrap">
    <section class="card">
      <h1>Interview Submitted</h1>
      <p>Thank you. Your interview scorecard was submitted successfully.</p>
      <p>This link is now closed.</p>
    </section>
  </div>
</body>
</html>`)
		return
	}
	_, _ = io.WriteString(w, `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Link Closed</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Manrope:wght@500;600;700;800&family=Space+Grotesk:wght@500;700&display=swap" rel="stylesheet">
<script>
(function () {
  var stored = localStorage.getItem("cfasuite-theme");
  var prefersDark = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
  var theme = stored === "light" || stored === "dark" ? stored : (prefersDark ? "dark" : "light");
  document.documentElement.classList.toggle("dark", theme === "dark");
})();
</script>
<style>
:root{--bg:#fff;--fg:#09090b;--card:#fff;--muted:#71717a;--border:#e4e4e7}
html.dark{--bg:#09090b;--fg:#fafafa;--card:#09090b;--muted:#a1a1aa;--border:#3f3f46}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font-family:"Manrope",sans-serif}
.wrap{max-width:760px;margin:0 auto;padding:4rem 1rem}
.card{border:1px solid var(--border);border-radius:12px;background:var(--card);padding:1rem}
h1{margin:0 0 .6rem;font-size:1.35rem;font-family:"Space Grotesk",sans-serif}
p{margin:0 0 .5rem;color:var(--muted);line-height:1.45}
</style>
</head>
<body>
  <div class="wrap">
    <section class="card">
      <h1>Link Closed</h1>
      <p>This interview link has already been used or deleted.</p>
      <p>Please contact your admin for a new link.</p>
    </section>
  </div>
</body>
</html>`)
}

func (s *server) locationTimePunchPage(w http.ResponseWriter, r *http.Request, locationNumber string) {
	location, err := s.fetchLocation(r, locationNumber)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	csrfToken, err := s.fetchCSRFToken(r)
	if err != nil {
		http.Redirect(w, r, "/?error=Session+expired", http.StatusFound)
		return
	}
	entries, err := s.fetchLocationTimePunchEntries(r, locationNumber, false)
	if err != nil {
		http.Error(w, "unable to load time punch entries", http.StatusBadGateway)
		return
	}
	archivedEntries, err := s.fetchLocationTimePunchEntries(r, locationNumber, true)
	if err != nil {
		http.Error(w, "unable to load archived time punch entries", http.StatusBadGateway)
		return
	}
	employees, err := s.fetchLocationEmployees(r, locationNumber)
	if err != nil {
		http.Error(w, "unable to load location employees", http.StatusBadGateway)
		return
	}
	entries = limitTimePunchEntries(entries, 50)
	archivedEntries = limitTimePunchEntries(archivedEntries, 50)
	if err := renderHTMLTemplate(w, s.timePunchTmpl, pageData{
		Location:                 location,
		CSRF:                     csrfToken,
		Employees:                employees,
		TimePunchEntries:         entries,
		ArchivedTimePunchEntries: archivedEntries,
		HasOpenTimePunchEntries:  len(entries) > 0,
		SuccessMessage:           r.URL.Query().Get("message"),
		Error:                    r.URL.Query().Get("error"),
	}); err != nil {
		http.Error(w, "template render failed", http.StatusInternalServerError)
		log.Printf("time punch template render failed: %v", err)
	}
}

func (s *server) locationTimeOffPage(w http.ResponseWriter, r *http.Request, locationNumber string) {
	location, err := s.fetchLocation(r, locationNumber)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	csrfToken, err := s.fetchCSRFToken(r)
	if err != nil {
		http.Redirect(w, r, "/?error=Session+expired", http.StatusFound)
		return
	}
	requests, err := s.fetchLocationTimeOffRequests(r, locationNumber, false)
	if err != nil {
		http.Error(w, "unable to load vacation requests", http.StatusBadGateway)
		return
	}
	employees, err := s.fetchLocationEmployees(r, locationNumber)
	if err != nil {
		http.Error(w, "unable to load location employees", http.StatusBadGateway)
		return
	}
	archivedRequests, err := s.fetchLocationTimeOffRequests(r, locationNumber, true)
	if err != nil {
		http.Error(w, "unable to load processed vacation requests", http.StatusBadGateway)
		return
	}
	hasOverdueTimeOffRequests, overdueTimeOffRequestCount := overdueTimeOffRequestStatus(requests, time.Now())
	hasUpcomingTimeOffRequests, upcomingTimeOffRequestCount := upcomingTimeOffRequestStatus(requests, time.Now(), 7)
	if err := renderHTMLTemplate(w, s.timeOffTmpl, pageData{
		Location:                    location,
		CSRF:                        csrfToken,
		Employees:                   employees,
		TimeOffRequests:             requests,
		ArchivedTimeOffRequests:     archivedRequests,
		HasOverdueTimeOffRequests:   hasOverdueTimeOffRequests,
		OverdueTimeOffRequestCount:  overdueTimeOffRequestCount,
		HasUpcomingTimeOffRequests:  hasUpcomingTimeOffRequests,
		UpcomingTimeOffRequestCount: upcomingTimeOffRequestCount,
		SuccessMessage:              r.URL.Query().Get("message"),
		Error:                       r.URL.Query().Get("error"),
	}); err != nil {
		http.Error(w, "template render failed", http.StatusInternalServerError)
		log.Printf("time off template render failed: %v", err)
	}
}

func (s *server) locationUniformsPage(w http.ResponseWriter, r *http.Request, locationNumber string) {
	location, err := s.fetchLocation(r, locationNumber)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	csrfToken, err := s.fetchCSRFToken(r)
	if err != nil {
		http.Redirect(w, r, "/?error=Session+expired", http.StatusFound)
		return
	}
	items, err := s.fetchLocationUniformItems(r, locationNumber)
	if err != nil {
		http.Error(w, "unable to load uniform items", http.StatusBadGateway)
		return
	}
	employees, err := s.fetchLocationEmployees(r, locationNumber)
	if err != nil {
		http.Error(w, "unable to load location employees", http.StatusBadGateway)
		return
	}
	orders, err := s.fetchLocationUniformOrders(r, locationNumber, false)
	if err != nil {
		http.Error(w, "unable to load uniform orders", http.StatusBadGateway)
		return
	}
	archivedOrders, err := s.fetchLocationUniformOrders(r, locationNumber, true)
	if err != nil {
		http.Error(w, "unable to load archived uniform orders", http.StatusBadGateway)
		return
	}
	hasPendingUniformOrders, pendingUniformOrderCount := unpurchasedUniformOrderStatus(orders)
	hasOutstandingUniformCharges, outstandingUniformChargeOrderCount := outstandingUniformChargesStatus(append(append([]uniformOrderView{}, orders...), archivedOrders...))
	if err := renderHTMLTemplate(w, s.uniformsTmpl, pageData{
		Location:                           location,
		CSRF:                               csrfToken,
		Employees:                          employees,
		UniformItems:                       items,
		UniformOrders:                      orders,
		HasPendingUniformOrders:            hasPendingUniformOrders,
		PendingUniformOrderCount:           pendingUniformOrderCount,
		HasOutstandingUniformCharges:       hasOutstandingUniformCharges,
		OutstandingUniformChargeOrderCount: outstandingUniformChargeOrderCount,
		SuccessMessage:                     r.URL.Query().Get("message"),
		Error:                              r.URL.Query().Get("error"),
	}); err != nil {
		http.Error(w, "template render failed", http.StatusInternalServerError)
		log.Printf("uniforms template render failed: %v", err)
	}
}

func (s *server) locationArchivedUniformOrdersPage(w http.ResponseWriter, r *http.Request, locationNumber string) {
	location, err := s.fetchLocation(r, locationNumber)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	csrfToken, err := s.fetchCSRFToken(r)
	if err != nil {
		http.Redirect(w, r, "/?error=Session+expired", http.StatusFound)
		return
	}
	archivedOrders, err := s.fetchLocationUniformOrders(r, locationNumber, true)
	if err != nil {
		http.Error(w, "unable to load archived uniform orders", http.StatusBadGateway)
		return
	}
	nameSet := make(map[string]struct{}, len(archivedOrders))
	employeeNames := make([]string, 0, len(archivedOrders))
	for _, order := range archivedOrders {
		name := strings.TrimSpace(order.TimePunchName)
		if name == "" {
			continue
		}
		key := strings.ToLower(name)
		if _, exists := nameSet[key]; exists {
			continue
		}
		nameSet[key] = struct{}{}
		employeeNames = append(employeeNames, name)
	}
	sort.Slice(employeeNames, func(i, j int) bool {
		return strings.ToLower(employeeNames[i]) < strings.ToLower(employeeNames[j])
	})
	search := strings.TrimSpace(r.URL.Query().Get("employee"))
	page := parsePositiveInt(r.URL.Query().Get("page"), 1)
	perPage := 50

	filtered := make([]uniformOrderView, 0, len(archivedOrders))
	if search == "" {
		filtered = archivedOrders
	} else {
		searchLower := strings.ToLower(search)
		for _, order := range archivedOrders {
			if strings.Contains(strings.ToLower(order.TimePunchName), searchLower) {
				filtered = append(filtered, order)
			}
		}
	}

	total := len(filtered)
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
	pageOrders := filtered[start:end]

	returnPath := "/admin/locations/" + url.PathEscape(locationNumber) + "/uniform-orders/archived"
	queryParts := make([]string, 0, 2)
	if page > 1 {
		queryParts = append(queryParts, "page="+strconv.Itoa(page))
	}
	if search != "" {
		queryParts = append(queryParts, "employee="+url.QueryEscape(search))
	}
	if len(queryParts) > 0 {
		returnPath += "?" + strings.Join(queryParts, "&")
	}

	if err := renderHTMLTemplate(w, s.uniformArchivedTmpl, pageData{
		Location:       location,
		CSRF:           csrfToken,
		ArchivedOrders: pageOrders,
		EmployeeNames:  employeeNames,
		Page:           page,
		HasPrev:        page > 1,
		HasNext:        page < totalPages,
		PrevPage:       max(1, page-1),
		NextPage:       page + 1,
		TotalCount:     total,
		Search:         search,
		ReturnPath:     returnPath,
		SuccessMessage: r.URL.Query().Get("message"),
		Error:          r.URL.Query().Get("error"),
	}); err != nil {
		http.Error(w, "template render failed", http.StatusInternalServerError)
		log.Printf("archived uniform orders template render failed: %v", err)
	}
}

func (s *server) locationUniformItemPage(w http.ResponseWriter, r *http.Request, locationNumber string, itemID int64) {
	location, err := s.fetchLocation(r, locationNumber)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	csrfToken, err := s.fetchCSRFToken(r)
	if err != nil {
		http.Redirect(w, r, "/?error=Session+expired", http.StatusFound)
		return
	}
	item, err := s.fetchLocationUniformItem(r, locationNumber, itemID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if err := renderHTMLTemplate(w, s.uniformItemTmpl, pageData{
		Location:       location,
		CSRF:           csrfToken,
		UniformItem:    item,
		SuccessMessage: r.URL.Query().Get("message"),
		Error:          r.URL.Query().Get("error"),
	}); err != nil {
		http.Error(w, "template render failed", http.StatusInternalServerError)
		log.Printf("uniform item template render failed: %v", err)
	}
}

func (s *server) createUniformItemProxy(w http.ResponseWriter, r *http.Request, locationNumber string) {
	if err := r.ParseMultipartForm(20 << 20); err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/uniforms?error=Invalid+upload", http.StatusFound)
		return
	}
	csrfToken := strings.TrimSpace(r.FormValue("csrf_token"))
	if csrfToken == "" {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/uniforms?error=Missing+csrf+token", http.StatusFound)
		return
	}
	file, header, err := r.FormFile("photo_file")
	if err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/uniforms?error=Image+file+is+required", http.StatusFound)
		return
	}
	defer file.Close()

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	_ = writer.WriteField("name", strings.TrimSpace(r.FormValue("name")))
	_ = writer.WriteField("price", strings.TrimSpace(r.FormValue("price")))
	_ = writer.WriteField("sizes", strings.TrimSpace(r.FormValue("sizes")))
	_ = writer.WriteField("size_fields", strings.TrimSpace(r.FormValue("size_fields")))
	for _, key := range []string{"crop_x", "crop_y", "crop_size"} {
		if value := strings.TrimSpace(r.FormValue(key)); value != "" {
			_ = writer.WriteField(key, value)
		}
	}
	part, err := writer.CreateFormFile("photo_file", header.Filename)
	if err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/uniforms?error=Unable+to+prepare+upload", http.StatusFound)
		return
	}
	if _, err := io.Copy(part, file); err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/uniforms?error=Unable+to+read+upload", http.StatusFound)
		return
	}
	if err := writer.Close(); err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/uniforms?error=Unable+to+finalize+upload", http.StatusFound)
		return
	}

	apiURL := s.apiBaseURL + "/api/admin/locations/" + url.PathEscape(locationNumber) + "/uniform-items"
	apiReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, apiURL, &body)
	if err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/uniforms?error=Unable+to+send+upload", http.StatusFound)
		return
	}
	copySessionCookieHeader(r, apiReq)
	apiReq.Header.Set("Content-Type", writer.FormDataContentType())
	apiReq.Header.Set(csrfHeaderName, csrfToken)
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/uniforms?error=Service+unavailable", http.StatusFound)
		return
	}
	defer apiResp.Body.Close()
	respBody, _ := io.ReadAll(apiResp.Body)
	if apiResp.StatusCode != http.StatusCreated && apiResp.StatusCode != http.StatusOK {
		msg := "unable to create uniform item"
		var payload map[string]string
		if err := json.Unmarshal(respBody, &payload); err == nil && strings.TrimSpace(payload["error"]) != "" {
			msg = payload["error"]
		}
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/uniforms?error="+url.QueryEscape(msg), http.StatusFound)
		return
	}
	http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/uniforms?message="+url.QueryEscape("Uniform item created"), http.StatusFound)
}

func (s *server) createUniformOrderProxy(w http.ResponseWriter, r *http.Request, locationNumber string) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/uniforms?error=Invalid+form+submission#order-uniform", http.StatusFound)
		return
	}
	csrfToken := strings.TrimSpace(r.FormValue("csrf_token"))
	if csrfToken == "" {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/uniforms?error=Missing+csrf+token#order-uniform", http.StatusFound)
		return
	}

	orderType := strings.TrimSpace(strings.ToLower(r.FormValue("order_type")))
	itemID := int64(0)
	if orderType != uniformSystemKeyShoes {
		parsedItemID, err := strconv.ParseInt(strings.TrimSpace(r.FormValue("item_id")), 10, 64)
		if err != nil || parsedItemID <= 0 {
			http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/uniforms?error=Invalid+uniform+item#order-uniform", http.StatusFound)
			return
		}
		itemID = parsedItemID
	}
	quantity, err := strconv.ParseInt(strings.TrimSpace(r.FormValue("quantity")), 10, 64)
	if err != nil || quantity <= 0 {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/uniforms?error=Quantity+must+be+at+least+1#order-uniform", http.StatusFound)
		return
	}

	orderPayload := map[string]any{
		"timePunchName": strings.TrimSpace(r.FormValue("time_punch_name")),
		"items": []map[string]any{
			{
				"itemId":         itemID,
				"size":           strings.TrimSpace(r.FormValue("size")),
				"sizeSelections": parseFormSizeSelections(r.PostForm["size_field_label"], r.PostForm["size_field_value"]),
				"sizeValues":     parseFormSizeValues(r.PostForm["size_field_value"]),
				"orderType":      orderType,
				"shoeItemNumber": strings.TrimSpace(r.FormValue("shoe_item_number")),
				"shoePrice":      strings.TrimSpace(r.FormValue("shoe_price")),
				"shoeUrl":        strings.TrimSpace(r.FormValue("shoe_url")),
				"note":           strings.TrimSpace(r.FormValue("note")),
				"quantity":       quantity,
			},
		},
	}
	body, _ := json.Marshal(orderPayload)
	orderReq, err := http.NewRequestWithContext(
		r.Context(),
		http.MethodPost,
		s.apiBaseURL+"/api/admin/locations/"+url.PathEscape(locationNumber)+"/uniform-orders",
		bytes.NewReader(body),
	)
	if err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/uniforms?error=Unable+to+create+uniform+order#order-uniform", http.StatusFound)
		return
	}
	copySessionCookieHeader(r, orderReq)
	orderReq.Header.Set("Content-Type", "application/json")
	orderReq.Header.Set(csrfHeaderName, csrfToken)
	orderResp, err := s.apiClient.Do(orderReq)
	if err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/uniforms?error=Service+unavailable#order-uniform", http.StatusFound)
		return
	}
	defer orderResp.Body.Close()
	orderRespBody, _ := io.ReadAll(orderResp.Body)
	if orderResp.StatusCode != http.StatusCreated && orderResp.StatusCode != http.StatusOK {
		msg := "unable to submit uniform order"
		var errPayload map[string]string
		if err := json.Unmarshal(orderRespBody, &errPayload); err == nil && strings.TrimSpace(errPayload["error"]) != "" {
			msg = errPayload["error"]
		}
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/uniforms?error="+url.QueryEscape(msg)+"#order-uniform", http.StatusFound)
		return
	}
	http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/uniforms?message="+url.QueryEscape("Uniform order submitted")+"#submitted-requests", http.StatusFound)
}

func (s *server) updateUniformItemProxy(w http.ResponseWriter, r *http.Request, locationNumber string, itemID int64) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/uniforms?error=Invalid+form+submission", http.StatusFound)
		return
	}
	csrfToken := strings.TrimSpace(r.FormValue("csrf_token"))
	nextPath := strings.TrimSpace(r.FormValue("next"))
	if nextPath == "" || !strings.HasPrefix(nextPath, "/") {
		nextPath = "/admin/locations/" + url.PathEscape(locationNumber) + "/uniforms"
	}
	if csrfToken == "" {
		http.Redirect(w, r, nextPath+"?error=Missing+csrf+token", http.StatusFound)
		return
	}
	payload := map[string]any{
		"name":       strings.TrimSpace(r.FormValue("name")),
		"price":      strings.TrimSpace(r.FormValue("price")),
		"sizes":      strings.TrimSpace(r.FormValue("sizes")),
		"sizeFields": strings.TrimSpace(r.FormValue("size_fields")),
	}
	body, _ := json.Marshal(payload)

	apiURL := s.apiBaseURL + "/api/admin/locations/" + url.PathEscape(locationNumber) + "/uniform-items/" + strconv.FormatInt(itemID, 10)
	apiReq, err := http.NewRequestWithContext(r.Context(), http.MethodPut, apiURL, bytes.NewReader(body))
	if err != nil {
		http.Redirect(w, r, nextPath+"?error=Unable+to+update+item", http.StatusFound)
		return
	}
	copySessionCookieHeader(r, apiReq)
	apiReq.Header.Set("Content-Type", "application/json")
	apiReq.Header.Set(csrfHeaderName, csrfToken)
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		http.Redirect(w, r, nextPath+"?error=Service+unavailable", http.StatusFound)
		return
	}
	defer apiResp.Body.Close()
	respBody, _ := io.ReadAll(apiResp.Body)
	if apiResp.StatusCode != http.StatusOK {
		msg := "unable to update uniform item"
		var errPayload map[string]string
		if err := json.Unmarshal(respBody, &errPayload); err == nil && strings.TrimSpace(errPayload["error"]) != "" {
			msg = errPayload["error"]
		}
		http.Redirect(w, r, nextPath+"?error="+url.QueryEscape(msg), http.StatusFound)
		return
	}
	http.Redirect(w, r, nextPath+"?message="+url.QueryEscape("Uniform item updated"), http.StatusFound)
}

func (s *server) deleteUniformItemProxy(w http.ResponseWriter, r *http.Request, locationNumber string, itemID int64) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/uniforms?error=Invalid+form+submission", http.StatusFound)
		return
	}
	csrfToken := strings.TrimSpace(r.FormValue("csrf_token"))
	if csrfToken == "" {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/uniforms?error=Missing+csrf+token", http.StatusFound)
		return
	}
	apiURL := s.apiBaseURL + "/api/admin/locations/" + url.PathEscape(locationNumber) + "/uniform-items/" + strconv.FormatInt(itemID, 10)
	apiReq, err := http.NewRequestWithContext(r.Context(), http.MethodDelete, apiURL, nil)
	if err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/uniforms?error=Unable+to+delete+item", http.StatusFound)
		return
	}
	copySessionCookieHeader(r, apiReq)
	apiReq.Header.Set(csrfHeaderName, csrfToken)
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/uniforms?error=Service+unavailable", http.StatusFound)
		return
	}
	defer apiResp.Body.Close()
	respBody, _ := io.ReadAll(apiResp.Body)
	if apiResp.StatusCode != http.StatusOK {
		msg := "unable to delete uniform item"
		var errPayload map[string]string
		if err := json.Unmarshal(respBody, &errPayload); err == nil && strings.TrimSpace(errPayload["error"]) != "" {
			msg = errPayload["error"]
		}
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/uniforms?error="+url.QueryEscape(msg), http.StatusFound)
		return
	}
	http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/uniforms?message="+url.QueryEscape("Uniform item deleted"), http.StatusFound)
}

func (s *server) archiveUniformOrderProxy(w http.ResponseWriter, r *http.Request, locationNumber string, orderID int64) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/uniforms?error=Invalid+form+submission", http.StatusFound)
		return
	}
	csrfToken := strings.TrimSpace(r.FormValue("csrf_token"))
	if csrfToken == "" {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/uniforms?error=Missing+csrf+token", http.StatusFound)
		return
	}
	apiURL := s.apiBaseURL + "/api/admin/locations/" + url.PathEscape(locationNumber) + "/uniform-orders/" + strconv.FormatInt(orderID, 10)
	apiReq, err := http.NewRequestWithContext(r.Context(), http.MethodPut, apiURL, nil)
	if err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/uniforms?error=Unable+to+archive+order", http.StatusFound)
		return
	}
	copySessionCookieHeader(r, apiReq)
	apiReq.Header.Set(csrfHeaderName, csrfToken)
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/uniforms?error=Service+unavailable", http.StatusFound)
		return
	}
	defer apiResp.Body.Close()
	respBody, _ := io.ReadAll(apiResp.Body)
	if apiResp.StatusCode != http.StatusOK {
		msg := "unable to archive uniform order"
		var errPayload map[string]string
		if err := json.Unmarshal(respBody, &errPayload); err == nil && strings.TrimSpace(errPayload["error"]) != "" {
			msg = errPayload["error"]
		}
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/uniforms?error="+url.QueryEscape(msg), http.StatusFound)
		return
	}
	http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/uniforms?message="+url.QueryEscape("Uniform order archived"), http.StatusFound)
}

func (s *server) updateUniformOrderLineSettlementProxy(w http.ResponseWriter, r *http.Request, locationNumber string, orderID, lineID int64) {
	basePath := "/admin/locations/" + url.PathEscape(locationNumber) + "/uniforms"
	redirectWithPanel := func(query string) string {
		if strings.TrimSpace(query) == "" {
			return basePath + "#submitted-requests"
		}
		return basePath + query + "#submitted-requests"
	}
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, redirectWithPanel("?error=Invalid+form+submission"), http.StatusFound)
		return
	}
	csrfToken := strings.TrimSpace(r.FormValue("csrf_token"))
	if csrfToken == "" {
		http.Redirect(w, r, redirectWithPanel("?error=Missing+csrf+token"), http.StatusFound)
		return
	}

	payload := map[string]any{
		"purchased":   strings.TrimSpace(r.FormValue("purchased")) == "on",
		"chargedBack": strings.TrimSpace(r.FormValue("charged_back")),
	}
	body, _ := json.Marshal(payload)

	apiURL := s.apiBaseURL + "/api/admin/locations/" + url.PathEscape(locationNumber) + "/uniform-orders/" + strconv.FormatInt(orderID, 10) + "/lines/" + strconv.FormatInt(lineID, 10)
	apiReq, err := http.NewRequestWithContext(r.Context(), http.MethodPut, apiURL, bytes.NewReader(body))
	if err != nil {
		http.Redirect(w, r, redirectWithPanel("?error=Unable+to+update+uniform+line"), http.StatusFound)
		return
	}
	copySessionCookieHeader(r, apiReq)
	apiReq.Header.Set(csrfHeaderName, csrfToken)
	apiReq.Header.Set("Content-Type", "application/json")
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		http.Redirect(w, r, redirectWithPanel("?error=Service+unavailable"), http.StatusFound)
		return
	}
	defer apiResp.Body.Close()
	respBody, _ := io.ReadAll(apiResp.Body)
	if apiResp.StatusCode != http.StatusOK {
		msg := "unable to update uniform line"
		var errPayload map[string]string
		if err := json.Unmarshal(respBody, &errPayload); err == nil && strings.TrimSpace(errPayload["error"]) != "" {
			msg = errPayload["error"]
		}
		http.Redirect(w, r, redirectWithPanel("?error="+url.QueryEscape(msg)), http.StatusFound)
		return
	}
	message := "Uniform line updated"
	var okPayload map[string]any
	if err := json.Unmarshal(respBody, &okPayload); err == nil {
		if raw, exists := okPayload["message"]; exists {
			if parsed, ok := raw.(string); ok && strings.TrimSpace(parsed) != "" {
				message = parsed
			}
		}
	}
	http.Redirect(w, r, redirectWithPanel("?message="+url.QueryEscape(message)), http.StatusFound)
}

func (s *server) deleteArchivedUniformOrderProxy(w http.ResponseWriter, r *http.Request, locationNumber string, orderID int64) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/uniforms?error=Invalid+form+submission", http.StatusFound)
		return
	}
	csrfToken := strings.TrimSpace(r.FormValue("csrf_token"))
	nextPath := strings.TrimSpace(r.FormValue("next"))
	if nextPath == "" || !strings.HasPrefix(nextPath, "/") {
		nextPath = "/admin/locations/" + url.PathEscape(locationNumber) + "/uniform-orders/archived"
	}
	if csrfToken == "" {
		http.Redirect(w, r, nextPath+"?error=Missing+csrf+token", http.StatusFound)
		return
	}
	apiURL := s.apiBaseURL + "/api/admin/locations/" + url.PathEscape(locationNumber) + "/uniform-orders/" + strconv.FormatInt(orderID, 10)
	apiReq, err := http.NewRequestWithContext(r.Context(), http.MethodDelete, apiURL, nil)
	if err != nil {
		http.Redirect(w, r, nextPath+"?error=Unable+to+delete+archived+order", http.StatusFound)
		return
	}
	copySessionCookieHeader(r, apiReq)
	apiReq.Header.Set(csrfHeaderName, csrfToken)
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		http.Redirect(w, r, nextPath+"?error=Service+unavailable", http.StatusFound)
		return
	}
	defer apiResp.Body.Close()
	respBody, _ := io.ReadAll(apiResp.Body)
	if apiResp.StatusCode != http.StatusOK {
		msg := "unable to delete archived uniform order"
		var errPayload map[string]string
		if err := json.Unmarshal(respBody, &errPayload); err == nil && strings.TrimSpace(errPayload["error"]) != "" {
			msg = errPayload["error"]
		}
		http.Redirect(w, r, nextPath+"?error="+url.QueryEscape(msg), http.StatusFound)
		return
	}
	http.Redirect(w, r, nextPath+"?message="+url.QueryEscape("Archived order deleted"), http.StatusFound)
}

func (s *server) moveUniformImageProxy(w http.ResponseWriter, r *http.Request, locationNumber string, itemID, imageID int64) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/uniforms?error=Invalid+form+submission", http.StatusFound)
		return
	}
	csrfToken := strings.TrimSpace(r.FormValue("csrf_token"))
	if csrfToken == "" {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/uniforms?error=Missing+csrf+token", http.StatusFound)
		return
	}
	direction := strings.ToLower(strings.TrimSpace(r.FormValue("direction")))
	nextPath := strings.TrimSpace(r.FormValue("next"))
	if nextPath == "" || !strings.HasPrefix(nextPath, "/") {
		nextPath = "/admin/locations/" + url.PathEscape(locationNumber) + "/uniforms"
	}
	if direction != "up" && direction != "down" {
		http.Redirect(w, r, nextPath+"?error=Invalid+reorder+direction", http.StatusFound)
		return
	}
	body, _ := json.Marshal(map[string]string{"direction": direction})
	apiURL := s.apiBaseURL + "/api/admin/locations/" + url.PathEscape(locationNumber) + "/uniform-items/" + strconv.FormatInt(itemID, 10) + "/images/" + strconv.FormatInt(imageID, 10) + "/move"
	apiReq, err := http.NewRequestWithContext(r.Context(), http.MethodPut, apiURL, bytes.NewReader(body))
	if err != nil {
		http.Redirect(w, r, nextPath+"?error=Unable+to+reorder+image", http.StatusFound)
		return
	}
	copySessionCookieHeader(r, apiReq)
	apiReq.Header.Set("Content-Type", "application/json")
	apiReq.Header.Set(csrfHeaderName, csrfToken)
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		http.Redirect(w, r, nextPath+"?error=Service+unavailable", http.StatusFound)
		return
	}
	defer apiResp.Body.Close()
	respBody, _ := io.ReadAll(apiResp.Body)
	if apiResp.StatusCode != http.StatusOK {
		msg := "unable to reorder uniform image"
		var errPayload map[string]string
		if err := json.Unmarshal(respBody, &errPayload); err == nil && strings.TrimSpace(errPayload["error"]) != "" {
			msg = errPayload["error"]
		}
		http.Redirect(w, r, nextPath+"?error="+url.QueryEscape(msg), http.StatusFound)
		return
	}
	http.Redirect(w, r, nextPath+"?message="+url.QueryEscape("Uniform image reordered"), http.StatusFound)
}

func (s *server) addUniformItemImagesProxy(w http.ResponseWriter, r *http.Request, locationNumber string, itemID int64) {
	if err := r.ParseMultipartForm(30 << 20); err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/uniform-items/"+strconv.FormatInt(itemID, 10)+"?error=Invalid+upload", http.StatusFound)
		return
	}
	csrfToken := strings.TrimSpace(r.FormValue("csrf_token"))
	if csrfToken == "" {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/uniform-items/"+strconv.FormatInt(itemID, 10)+"?error=Missing+csrf+token", http.StatusFound)
		return
	}
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	file, header, err := r.FormFile("photo_file")
	if err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/uniform-items/"+strconv.FormatInt(itemID, 10)+"?error=Photo+file+is+required", http.StatusFound)
		return
	}
	defer file.Close()
	dst, err := writer.CreateFormFile("photo_file", header.Filename)
	if err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/uniform-items/"+strconv.FormatInt(itemID, 10)+"?error=Unable+to+prepare+upload", http.StatusFound)
		return
	}
	if _, err := io.Copy(dst, file); err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/uniform-items/"+strconv.FormatInt(itemID, 10)+"?error=Unable+to+read+upload", http.StatusFound)
		return
	}
	for _, key := range []string{"crop_x", "crop_y", "crop_size"} {
		if value := strings.TrimSpace(r.FormValue(key)); value != "" {
			_ = writer.WriteField(key, value)
		}
	}
	if err := writer.Close(); err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/uniform-items/"+strconv.FormatInt(itemID, 10)+"?error=Unable+to+finalize+upload", http.StatusFound)
		return
	}
	apiURL := s.apiBaseURL + "/api/admin/locations/" + url.PathEscape(locationNumber) + "/uniform-items/" + strconv.FormatInt(itemID, 10) + "/images"
	apiReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, apiURL, &body)
	if err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/uniform-items/"+strconv.FormatInt(itemID, 10)+"?error=Unable+to+send+upload", http.StatusFound)
		return
	}
	copySessionCookieHeader(r, apiReq)
	apiReq.Header.Set("Content-Type", writer.FormDataContentType())
	apiReq.Header.Set(csrfHeaderName, csrfToken)
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/uniform-items/"+strconv.FormatInt(itemID, 10)+"?error=Service+unavailable", http.StatusFound)
		return
	}
	defer apiResp.Body.Close()
	respBody, _ := io.ReadAll(apiResp.Body)
	if apiResp.StatusCode != http.StatusOK {
		msg := "unable to upload gallery images"
		var errPayload map[string]string
		if err := json.Unmarshal(respBody, &errPayload); err == nil && strings.TrimSpace(errPayload["error"]) != "" {
			msg = errPayload["error"]
		}
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/uniform-items/"+strconv.FormatInt(itemID, 10)+"?error="+url.QueryEscape(msg), http.StatusFound)
		return
	}
	http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/uniform-items/"+strconv.FormatInt(itemID, 10)+"?message="+url.QueryEscape("Gallery images added"), http.StatusFound)
}

func (s *server) deleteUniformItemImageProxy(w http.ResponseWriter, r *http.Request, locationNumber string, itemID, imageID int64) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/uniform-items/"+strconv.FormatInt(itemID, 10)+"?error=Invalid+form+submission", http.StatusFound)
		return
	}
	csrfToken := strings.TrimSpace(r.FormValue("csrf_token"))
	if csrfToken == "" {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/uniform-items/"+strconv.FormatInt(itemID, 10)+"?error=Missing+csrf+token", http.StatusFound)
		return
	}
	apiURL := s.apiBaseURL + "/api/admin/locations/" + url.PathEscape(locationNumber) + "/uniform-items/" + strconv.FormatInt(itemID, 10) + "/images/" + strconv.FormatInt(imageID, 10)
	apiReq, err := http.NewRequestWithContext(r.Context(), http.MethodDelete, apiURL, nil)
	if err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/uniform-items/"+strconv.FormatInt(itemID, 10)+"?error=Unable+to+delete+image", http.StatusFound)
		return
	}
	copySessionCookieHeader(r, apiReq)
	apiReq.Header.Set(csrfHeaderName, csrfToken)
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/uniform-items/"+strconv.FormatInt(itemID, 10)+"?error=Service+unavailable", http.StatusFound)
		return
	}
	defer apiResp.Body.Close()
	respBody, _ := io.ReadAll(apiResp.Body)
	if apiResp.StatusCode != http.StatusOK {
		msg := "unable to delete image"
		var errPayload map[string]string
		if err := json.Unmarshal(respBody, &errPayload); err == nil && strings.TrimSpace(errPayload["error"]) != "" {
			msg = errPayload["error"]
		}
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/uniform-items/"+strconv.FormatInt(itemID, 10)+"?error="+url.QueryEscape(msg), http.StatusFound)
		return
	}
	http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/uniform-items/"+strconv.FormatInt(itemID, 10)+"?message="+url.QueryEscape("Image deleted"), http.StatusFound)
}

func (s *server) locationBusinessDaysPage(w http.ResponseWriter, r *http.Request, locationNumber string) {
	location, err := s.fetchLocation(r, locationNumber)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	csrfToken, err := s.fetchCSRFToken(r)
	if err != nil {
		http.Redirect(w, r, "/?error=Session+expired", http.StatusFound)
		return
	}
	businessDays, err := s.fetchLocationBusinessDays(r, locationNumber)
	if err != nil {
		http.Error(w, "unable to load business days", http.StatusBadGateway)
		return
	}
	if err := renderHTMLTemplate(w, s.businessDaysTmpl, pageData{
		Location:       location,
		CSRF:           csrfToken,
		BusinessDays:   businessDays,
		SuccessMessage: r.URL.Query().Get("message"),
		Error:          r.URL.Query().Get("error"),
	}); err != nil {
		http.Error(w, "template render failed", http.StatusInternalServerError)
		log.Printf("business days template render failed: %v", err)
	}
}

func (s *server) openBusinessDayFromPicker(w http.ResponseWriter, r *http.Request, locationNumber string) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/business-days?error=Invalid+form+submission", http.StatusFound)
		return
	}
	selectedDate := strings.TrimSpace(r.FormValue("selected_date"))
	if selectedDate == "" {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/business-days?error=Date+is+required", http.StatusFound)
		return
	}
	if _, err := time.Parse("2006-01-02", selectedDate); err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/business-days?error=Date+must+use+YYYY-MM-DD", http.StatusFound)
		return
	}
	if day, _ := time.Parse("2006-01-02", selectedDate); day.Weekday() == time.Sunday {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/business-days?error=Sunday+cannot+be+used+as+a+business+day", http.StatusFound)
		return
	}
	http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/business-days/"+url.PathEscape(selectedDate), http.StatusFound)
}

func (s *server) locationBusinessDayPage(w http.ResponseWriter, r *http.Request, locationNumber, businessDate string) {
	location, err := s.fetchLocation(r, locationNumber)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	csrfToken, err := s.fetchCSRFToken(r)
	if err != nil {
		http.Redirect(w, r, "/?error=Session+expired", http.StatusFound)
		return
	}
	day, err := s.fetchOrCreateBusinessDay(r, locationNumber, businessDate)
	if err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/business-days?error=Unable+to+open+business+day", http.StatusFound)
		return
	}
	if err := renderHTMLTemplate(w, s.businessDayTmpl, pageData{
		Location:       location,
		CSRF:           csrfToken,
		BusinessDay:    day,
		SuccessMessage: r.URL.Query().Get("message"),
		Error:          r.URL.Query().Get("error"),
	}); err != nil {
		http.Error(w, "template render failed", http.StatusInternalServerError)
		log.Printf("business day detail template render failed: %v", err)
	}
}

func (s *server) updateBusinessDayProxy(w http.ResponseWriter, r *http.Request, locationNumber, businessDate string) {
	csrfToken := strings.TrimSpace(r.Header.Get(csrfHeaderName))
	if csrfToken == "" {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "csrf token is required"})
		return
	}
	var req updateBusinessDayRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	body, _ := json.Marshal(req)
	apiURL := s.apiBaseURL + "/api/admin/locations/" + url.PathEscape(locationNumber) + "/business-days/" + url.PathEscape(businessDate)
	apiReq, err := http.NewRequestWithContext(r.Context(), http.MethodPut, apiURL, bytes.NewReader(body))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "upstream request failed"})
		return
	}
	copySessionCookieHeader(r, apiReq)
	apiReq.Header.Set("Content-Type", "application/json")
	apiReq.Header.Set(csrfHeaderName, csrfToken)
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "upstream service unavailable"})
		return
	}
	defer apiResp.Body.Close()
	respBody, _ := io.ReadAll(apiResp.Body)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(apiResp.StatusCode)
	_, _ = w.Write(respBody)
}

func (s *server) openBusinessDayInlineProxy(w http.ResponseWriter, r *http.Request, locationNumber string) {
	csrfToken := strings.TrimSpace(r.Header.Get(csrfHeaderName))
	if csrfToken == "" {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "csrf token is required"})
		return
	}
	var payload map[string]string
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	businessDate := strings.TrimSpace(payload["businessDate"])
	if businessDate == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "business date is required"})
		return
	}
	apiURL := s.apiBaseURL + "/api/admin/locations/" + url.PathEscape(locationNumber) + "/business-days/" + url.PathEscape(businessDate)
	apiReq, err := http.NewRequestWithContext(r.Context(), http.MethodGet, apiURL, nil)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "upstream request failed"})
		return
	}
	copySessionCookieHeader(r, apiReq)
	apiReq.Header.Set(csrfHeaderName, csrfToken)
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "upstream service unavailable"})
		return
	}
	defer apiResp.Body.Close()
	respBody, _ := io.ReadAll(apiResp.Body)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(apiResp.StatusCode)
	_, _ = w.Write(respBody)
}

func (s *server) deleteLocationTimePunchEntryProxy(w http.ResponseWriter, r *http.Request, locationNumber string, entryID int64) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/time-punch?error=Invalid+form+submission", http.StatusFound)
		return
	}
	csrfToken := strings.TrimSpace(r.FormValue("csrf_token"))
	if csrfToken == "" {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/time-punch?error=Missing+csrf+token", http.StatusFound)
		return
	}

	apiURL := s.apiBaseURL + "/api/admin/locations/" + url.PathEscape(locationNumber) + "/time-punch/" + strconv.FormatInt(entryID, 10)
	apiReq, err := http.NewRequestWithContext(r.Context(), http.MethodDelete, apiURL, nil)
	if err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/time-punch?error=Unable+to+delete+entry", http.StatusFound)
		return
	}
	copySessionCookieHeader(r, apiReq)
	apiReq.Header.Set(csrfHeaderName, csrfToken)

	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/time-punch?error=Service+unavailable", http.StatusFound)
		return
	}
	defer apiResp.Body.Close()
	respBody, _ := io.ReadAll(apiResp.Body)
	if apiResp.StatusCode != http.StatusOK {
		msg := "unable to delete time punch entry"
		var payload map[string]string
		if err := json.Unmarshal(respBody, &payload); err == nil && strings.TrimSpace(payload["error"]) != "" {
			msg = payload["error"]
		}
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/time-punch?error="+url.QueryEscape(msg), http.StatusFound)
		return
	}
	http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/time-punch?message="+url.QueryEscape("Time punch entry deleted"), http.StatusFound)
}

func (s *server) archiveLocationTimePunchEntryProxy(w http.ResponseWriter, r *http.Request, locationNumber string, entryID int64) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/time-punch?error=Invalid+form+submission#view-punches", http.StatusFound)
		return
	}
	csrfToken := strings.TrimSpace(r.FormValue("csrf_token"))
	if csrfToken == "" {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/time-punch?error=Missing+csrf+token#view-punches", http.StatusFound)
		return
	}
	apiURL := s.apiBaseURL + "/api/admin/locations/" + url.PathEscape(locationNumber) + "/time-punch/" + strconv.FormatInt(entryID, 10) + "/archive"
	apiReq, err := http.NewRequestWithContext(r.Context(), http.MethodPut, apiURL, nil)
	if err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/time-punch?error=Unable+to+complete+entry#view-punches", http.StatusFound)
		return
	}
	copySessionCookieHeader(r, apiReq)
	apiReq.Header.Set(csrfHeaderName, csrfToken)
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/time-punch?error=Service+unavailable#view-punches", http.StatusFound)
		return
	}
	defer apiResp.Body.Close()
	respBody, _ := io.ReadAll(apiResp.Body)
	if apiResp.StatusCode != http.StatusOK {
		msg := "unable to complete time punch entry"
		var payload map[string]string
		if err := json.Unmarshal(respBody, &payload); err == nil && strings.TrimSpace(payload["error"]) != "" {
			msg = payload["error"]
		}
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/time-punch?error="+url.QueryEscape(msg)+"#view-punches", http.StatusFound)
		return
	}
	http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/time-punch?message="+url.QueryEscape("Time punch entry marked completed")+"#completed-punches", http.StatusFound)
}

func (s *server) createLocationTimePunchEntryProxy(w http.ResponseWriter, r *http.Request, locationNumber string) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/time-punch?error=Invalid+form+submission#create-punch", http.StatusFound)
		return
	}
	csrfToken := strings.TrimSpace(r.FormValue("csrf_token"))
	if csrfToken == "" {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/time-punch?error=Missing+csrf+token#create-punch", http.StatusFound)
		return
	}
	payload := map[string]any{
		"timePunchName":            strings.TrimSpace(r.FormValue("time_punch_name")),
		"punchDate":                strings.TrimSpace(r.FormValue("punch_date")),
		"timeIn":                   strings.TrimSpace(r.FormValue("time_in")),
		"timeOut":                  strings.TrimSpace(r.FormValue("time_out")),
		"note":                     strings.TrimSpace(r.FormValue("note")),
		"forgotBreakClockInReturn": strings.TrimSpace(r.FormValue("forgot_break_clock_in_return")) != "",
	}
	body, _ := json.Marshal(payload)
	apiURL := s.apiBaseURL + "/api/admin/locations/" + url.PathEscape(locationNumber) + "/time-punch"
	apiReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, apiURL, bytes.NewReader(body))
	if err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/time-punch?error=Unable+to+create+entry#create-punch", http.StatusFound)
		return
	}
	copySessionCookieHeader(r, apiReq)
	apiReq.Header.Set("Content-Type", "application/json")
	apiReq.Header.Set(csrfHeaderName, csrfToken)
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/time-punch?error=Service+unavailable#create-punch", http.StatusFound)
		return
	}
	defer apiResp.Body.Close()
	respBody, _ := io.ReadAll(apiResp.Body)
	if apiResp.StatusCode != http.StatusCreated && apiResp.StatusCode != http.StatusOK {
		msg := "unable to create time punch entry"
		var payload map[string]string
		if err := json.Unmarshal(respBody, &payload); err == nil && strings.TrimSpace(payload["error"]) != "" {
			msg = payload["error"]
		}
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/time-punch?error="+url.QueryEscape(msg)+"#create-punch", http.StatusFound)
		return
	}
	http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/time-punch?message="+url.QueryEscape("Time punch submitted")+"#view-punches", http.StatusFound)
}

func (s *server) archiveTimeOffRequestProxy(w http.ResponseWriter, r *http.Request, locationNumber string, requestID int64) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/time-off?error=Invalid+form+submission#view-requests", http.StatusFound)
		return
	}
	csrfToken := strings.TrimSpace(r.FormValue("csrf_token"))
	if csrfToken == "" {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/time-off?error=Missing+csrf+token#view-requests", http.StatusFound)
		return
	}
	apiURL := s.apiBaseURL + "/api/admin/locations/" + url.PathEscape(locationNumber) + "/time-off/" + strconv.FormatInt(requestID, 10)
	apiReq, err := http.NewRequestWithContext(r.Context(), http.MethodPut, apiURL, nil)
	if err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/time-off?error=Unable+to+process+request#view-requests", http.StatusFound)
		return
	}
	copySessionCookieHeader(r, apiReq)
	apiReq.Header.Set(csrfHeaderName, csrfToken)
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/time-off?error=Service+unavailable#view-requests", http.StatusFound)
		return
	}
	defer apiResp.Body.Close()
	respBody, _ := io.ReadAll(apiResp.Body)
	if apiResp.StatusCode != http.StatusOK {
		msg := "unable to process vacation request"
		var errPayload map[string]string
		if err := json.Unmarshal(respBody, &errPayload); err == nil && strings.TrimSpace(errPayload["error"]) != "" {
			msg = errPayload["error"]
		}
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/time-off?error="+url.QueryEscape(msg)+"#view-requests", http.StatusFound)
		return
	}
	http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/time-off?message="+url.QueryEscape("Vacation request processed")+"#processed-requests", http.StatusFound)
}

func (s *server) createLocationTimeOffRequestProxy(w http.ResponseWriter, r *http.Request, locationNumber string) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/time-off?error=Invalid+form+submission#create-request", http.StatusFound)
		return
	}
	csrfToken := strings.TrimSpace(r.FormValue("csrf_token"))
	if csrfToken == "" {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/time-off?error=Missing+csrf+token#create-request", http.StatusFound)
		return
	}
	payload := map[string]string{
		"timePunchName": strings.TrimSpace(r.FormValue("time_punch_name")),
		"startDate":     strings.TrimSpace(r.FormValue("start_date")),
		"endDate":       strings.TrimSpace(r.FormValue("end_date")),
	}
	body, _ := json.Marshal(payload)
	apiURL := s.apiBaseURL + "/api/admin/locations/" + url.PathEscape(locationNumber) + "/time-off"
	apiReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, apiURL, bytes.NewReader(body))
	if err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/time-off?error=Unable+to+create+request#create-request", http.StatusFound)
		return
	}
	copySessionCookieHeader(r, apiReq)
	apiReq.Header.Set("Content-Type", "application/json")
	apiReq.Header.Set(csrfHeaderName, csrfToken)
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/time-off?error=Service+unavailable#create-request", http.StatusFound)
		return
	}
	defer apiResp.Body.Close()
	respBody, _ := io.ReadAll(apiResp.Body)
	if apiResp.StatusCode != http.StatusCreated && apiResp.StatusCode != http.StatusOK {
		msg := "unable to create vacation request"
		var errPayload map[string]string
		if err := json.Unmarshal(respBody, &errPayload); err == nil && strings.TrimSpace(errPayload["error"]) != "" {
			msg = errPayload["error"]
		}
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/time-off?error="+url.QueryEscape(msg)+"#create-request", http.StatusFound)
		return
	}
	http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/time-off?message="+url.QueryEscape("Vacation request submitted")+"#view-requests", http.StatusFound)
}

func (s *server) createLocationDepartmentProxy(w http.ResponseWriter, r *http.Request, locationNumber string) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/departments?error=Invalid+form+submission#create-department", http.StatusFound)
		return
	}
	csrfToken := strings.TrimSpace(r.FormValue("csrf_token"))
	if csrfToken == "" {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/departments?error=Missing+csrf+token#create-department", http.StatusFound)
		return
	}
	payload := map[string]string{
		"name": strings.TrimSpace(r.FormValue("name")),
	}
	body, _ := json.Marshal(payload)
	apiReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, s.apiBaseURL+"/api/admin/locations/"+url.PathEscape(locationNumber)+"/departments", bytes.NewReader(body))
	if err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/departments?error=Unable+to+create+department#create-department", http.StatusFound)
		return
	}
	copySessionCookieHeader(r, apiReq)
	apiReq.Header.Set("Content-Type", "application/json")
	apiReq.Header.Set(csrfHeaderName, csrfToken)
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/departments?error=Service+unavailable#create-department", http.StatusFound)
		return
	}
	defer apiResp.Body.Close()
	respBody, _ := io.ReadAll(apiResp.Body)
	if apiResp.StatusCode != http.StatusCreated && apiResp.StatusCode != http.StatusOK {
		msg := "unable to create department"
		var errPayload map[string]string
		if err := json.Unmarshal(respBody, &errPayload); err == nil && strings.TrimSpace(errPayload["error"]) != "" {
			msg = errPayload["error"]
		}
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/departments?error="+url.QueryEscape(msg)+"#create-department", http.StatusFound)
		return
	}
	http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/departments?message="+url.QueryEscape("Department created")+"#view-departments", http.StatusFound)
}

func (s *server) createLocationJobProxy(w http.ResponseWriter, r *http.Request, locationNumber string) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/departments?error=Invalid+form+submission#create-job", http.StatusFound)
		return
	}
	csrfToken := strings.TrimSpace(r.FormValue("csrf_token"))
	if csrfToken == "" {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/departments?error=Missing+csrf+token#create-job", http.StatusFound)
		return
	}
	payload := map[string]any{
		"name":      strings.TrimSpace(r.FormValue("name")),
		"payType":   strings.TrimSpace(r.FormValue("pay_type")),
		"payAmount": strings.TrimSpace(r.FormValue("pay_amount")),
	}
	body, _ := json.Marshal(payload)
	apiReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, s.apiBaseURL+"/api/admin/locations/"+url.PathEscape(locationNumber)+"/jobs", bytes.NewReader(body))
	if err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/departments?error=Unable+to+create+pay+band#create-job", http.StatusFound)
		return
	}
	copySessionCookieHeader(r, apiReq)
	apiReq.Header.Set("Content-Type", "application/json")
	apiReq.Header.Set(csrfHeaderName, csrfToken)
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/departments?error=Service+unavailable#create-job", http.StatusFound)
		return
	}
	defer apiResp.Body.Close()
	respBody, _ := io.ReadAll(apiResp.Body)
	if apiResp.StatusCode != http.StatusCreated && apiResp.StatusCode != http.StatusOK {
		msg := "unable to create pay band"
		var errPayload map[string]string
		if err := json.Unmarshal(respBody, &errPayload); err == nil && strings.TrimSpace(errPayload["error"]) != "" {
			msg = errPayload["error"]
		}
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/departments?error="+url.QueryEscape(msg)+"#create-job", http.StatusFound)
		return
	}
	http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/departments?message="+url.QueryEscape("Pay band created")+"#view-jobs", http.StatusFound)
}

func (s *server) updateLocationJobProxy(w http.ResponseWriter, r *http.Request, locationNumber string, jobID int64) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/departments?error=Invalid+form+submission#view-jobs", http.StatusFound)
		return
	}
	csrfToken := strings.TrimSpace(r.FormValue("csrf_token"))
	if csrfToken == "" {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/departments?error=Missing+csrf+token#view-jobs", http.StatusFound)
		return
	}
	payload := map[string]any{
		"name":      strings.TrimSpace(r.FormValue("name")),
		"payType":   strings.TrimSpace(r.FormValue("pay_type")),
		"payAmount": strings.TrimSpace(r.FormValue("pay_amount")),
	}
	body, _ := json.Marshal(payload)
	apiReq, err := http.NewRequestWithContext(
		r.Context(),
		http.MethodPut,
		s.apiBaseURL+"/api/admin/locations/"+url.PathEscape(locationNumber)+"/jobs/"+strconv.FormatInt(jobID, 10),
		bytes.NewReader(body),
	)
	if err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/departments?error=Unable+to+update+pay+band#view-jobs", http.StatusFound)
		return
	}
	copySessionCookieHeader(r, apiReq)
	apiReq.Header.Set("Content-Type", "application/json")
	apiReq.Header.Set(csrfHeaderName, csrfToken)
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/departments?error=Service+unavailable#view-jobs", http.StatusFound)
		return
	}
	defer apiResp.Body.Close()
	respBody, _ := io.ReadAll(apiResp.Body)
	if apiResp.StatusCode != http.StatusOK {
		msg := "unable to update pay band"
		var errPayload map[string]string
		if err := json.Unmarshal(respBody, &errPayload); err == nil && strings.TrimSpace(errPayload["error"]) != "" {
			msg = errPayload["error"]
		}
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/departments?error="+url.QueryEscape(msg)+"#view-jobs", http.StatusFound)
		return
	}
	http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/departments?message="+url.QueryEscape("Pay band updated")+"#view-jobs", http.StatusFound)
}

func (s *server) assignLocationJobDepartmentsProxy(w http.ResponseWriter, r *http.Request, locationNumber string, jobID int64) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/departments?error=Invalid+form+submission#view-jobs", http.StatusFound)
		return
	}
	csrfToken, err := s.fetchCSRFToken(r)
	if err != nil || strings.TrimSpace(csrfToken) == "" {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/departments?error=Session+expired#view-jobs", http.StatusFound)
		return
	}
	departmentIDs := make([]int64, 0, len(r.Form["department_ids"]))
	for _, raw := range r.Form["department_ids"] {
		id := parsePositiveInt(strings.TrimSpace(raw), 0)
		if id > 0 {
			departmentIDs = append(departmentIDs, int64(id))
		}
	}
	payload := map[string]any{"departmentIds": departmentIDs}
	body, _ := json.Marshal(payload)
	apiReq, err := http.NewRequestWithContext(
		r.Context(),
		http.MethodPut,
		s.apiBaseURL+"/api/admin/locations/"+url.PathEscape(locationNumber)+"/jobs/"+strconv.FormatInt(jobID, 10)+"/departments",
		bytes.NewReader(body),
	)
	if err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/departments?error=Unable+to+assign+departments#view-jobs", http.StatusFound)
		return
	}
	copySessionCookieHeader(r, apiReq)
	apiReq.Header.Set("Content-Type", "application/json")
	apiReq.Header.Set(csrfHeaderName, csrfToken)
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/departments?error=Service+unavailable#view-jobs", http.StatusFound)
		return
	}
	defer apiResp.Body.Close()
	respBody, _ := io.ReadAll(apiResp.Body)
	if apiResp.StatusCode != http.StatusOK {
		msg := "unable to assign departments"
		var errPayload map[string]string
		if err := json.Unmarshal(respBody, &errPayload); err == nil && strings.TrimSpace(errPayload["error"]) != "" {
			msg = errPayload["error"]
		} else if trimmed := strings.TrimSpace(string(respBody)); trimmed != "" {
			msg = trimmed
		} else {
			msg = "unable to assign departments (status " + strconv.Itoa(apiResp.StatusCode) + ")"
		}
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/departments?error="+url.QueryEscape(msg)+"#view-jobs", http.StatusFound)
		return
	}
	http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/departments?message="+url.QueryEscape("Job departments updated")+"#view-jobs", http.StatusFound)
}

func (s *server) importLocationEmployeesProxy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	trimmed := strings.TrimPrefix(r.URL.Path, "/admin/locations/")
	trimmed = strings.TrimSuffix(trimmed, "/employees/import")
	trimmed = strings.Trim(trimmed, "/")
	if trimmed == "" {
		http.NotFound(w, r)
		return
	}
	locationNumber, err := url.PathUnescape(trimmed)
	if err != nil || strings.TrimSpace(locationNumber) == "" {
		http.NotFound(w, r)
		return
	}

	if err := r.ParseMultipartForm(20 << 20); err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees?error=Invalid+upload#bulk-import", http.StatusFound)
		return
	}
	file, header, err := r.FormFile("bio_file")
	if err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees?error=Employee+Bio+Reader+file+is+required#bulk-import", http.StatusFound)
		return
	}
	defer file.Close()

	csrfToken := strings.TrimSpace(r.FormValue("csrf_token"))
	if csrfToken == "" {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees?error=Missing+csrf+token#bulk-import", http.StatusFound)
		return
	}

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("bio_file", header.Filename)
	if err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees?error=Unable+to+prepare+upload#bulk-import", http.StatusFound)
		return
	}
	if _, err := io.Copy(part, file); err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees?error=Unable+to+read+upload#bulk-import", http.StatusFound)
		return
	}
	if err := writer.Close(); err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees?error=Unable+to+finalize+upload#bulk-import", http.StatusFound)
		return
	}

	apiURL := s.apiBaseURL + "/api/admin/locations/" + url.PathEscape(locationNumber) + "/employees/import"
	apiReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, apiURL, &body)
	if err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees?error=Unable+to+send+upload#bulk-import", http.StatusFound)
		return
	}
	copySessionCookieHeader(r, apiReq)
	apiReq.Header.Set("Content-Type", writer.FormDataContentType())
	apiReq.Header.Set(csrfHeaderName, csrfToken)

	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees?error=Import+service+unavailable#bulk-import", http.StatusFound)
		return
	}
	defer apiResp.Body.Close()

	respBody, _ := io.ReadAll(apiResp.Body)
	if apiResp.StatusCode != http.StatusOK {
		msg := "unable to import bio reader"
		var payload map[string]string
		if err := json.Unmarshal(respBody, &payload); err == nil {
			if payload["error"] != "" {
				msg = payload["error"]
			}
		}
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees?error="+url.QueryEscape(msg)+"#bulk-import", http.StatusFound)
		return
	}

	http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees?message="+url.QueryEscape("Bio reader imported successfully")+"#bulk-import", http.StatusFound)
}

func (s *server) importLocationBirthdatesProxy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	trimmed := strings.TrimPrefix(r.URL.Path, "/admin/locations/")
	trimmed = strings.TrimSuffix(trimmed, "/employees/birthdates/import")
	trimmed = strings.Trim(trimmed, "/")
	if trimmed == "" {
		http.NotFound(w, r)
		return
	}
	locationNumber, err := url.PathUnescape(trimmed)
	if err != nil || strings.TrimSpace(locationNumber) == "" {
		http.NotFound(w, r)
		return
	}

	if err := r.ParseMultipartForm(20 << 20); err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees?error=Invalid+upload#bulk-import", http.StatusFound)
		return
	}
	file, header, err := r.FormFile("birthdate_file")
	if err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees?error=Birthday+report+file+is+required#bulk-import", http.StatusFound)
		return
	}
	defer file.Close()

	csrfToken := strings.TrimSpace(r.FormValue("csrf_token"))
	if csrfToken == "" {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees?error=Missing+csrf+token#bulk-import", http.StatusFound)
		return
	}

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("birthdate_file", header.Filename)
	if err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees?error=Unable+to+prepare+upload#bulk-import", http.StatusFound)
		return
	}
	if _, err := io.Copy(part, file); err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees?error=Unable+to+read+upload#bulk-import", http.StatusFound)
		return
	}
	if err := writer.Close(); err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees?error=Unable+to+finalize+upload#bulk-import", http.StatusFound)
		return
	}

	apiURL := s.apiBaseURL + "/api/admin/locations/" + url.PathEscape(locationNumber) + "/employees/birthdates/import"
	apiReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, apiURL, &body)
	if err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees?error=Unable+to+send+upload#bulk-import", http.StatusFound)
		return
	}
	copySessionCookieHeader(r, apiReq)
	apiReq.Header.Set("Content-Type", writer.FormDataContentType())
	apiReq.Header.Set(csrfHeaderName, csrfToken)

	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees?error=Import+service+unavailable#bulk-import", http.StatusFound)
		return
	}
	defer apiResp.Body.Close()

	respBody, _ := io.ReadAll(apiResp.Body)
	if apiResp.StatusCode != http.StatusOK {
		msg := "unable to import birthday report"
		var payload map[string]string
		if err := json.Unmarshal(respBody, &payload); err == nil {
			if payload["error"] != "" {
				msg = payload["error"]
			}
		}
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees?error="+url.QueryEscape(msg)+"#bulk-import", http.StatusFound)
		return
	}

	http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees?message="+url.QueryEscape("Birthday report imported successfully")+"#bulk-import", http.StatusFound)
}

func (s *server) updateEmployeeDetailsProxy(w http.ResponseWriter, r *http.Request, locationNumber, timePunchName string) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees/"+url.PathEscape(timePunchName)+"?error="+url.QueryEscape("Invalid employee update form")+"#employee-edit", http.StatusFound)
		return
	}
	csrfToken := strings.TrimSpace(r.FormValue("csrf_token"))
	if csrfToken == "" {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees/"+url.PathEscape(timePunchName)+"?error="+url.QueryEscape("Missing csrf token")+"#employee-edit", http.StatusFound)
		return
	}
	birthMonth := strings.TrimSpace(r.FormValue("birthday_month"))
	birthDay := strings.TrimSpace(r.FormValue("birthday_day"))
	birthYear := strings.TrimSpace(r.FormValue("birthday_year"))
	birthday := ""
	if birthMonth != "" || birthDay != "" || birthYear != "" {
		if birthMonth == "" || birthDay == "" || birthYear == "" {
			http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees/"+url.PathEscape(timePunchName)+"?error="+url.QueryEscape("Birthday must include month, day, and year")+"#employee-edit", http.StatusFound)
			return
		}
		monthNum, err := strconv.Atoi(birthMonth)
		if err != nil || monthNum < 1 || monthNum > 12 {
			http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees/"+url.PathEscape(timePunchName)+"?error="+url.QueryEscape("Birthday month is invalid")+"#employee-edit", http.StatusFound)
			return
		}
		dayNum, err := strconv.Atoi(birthDay)
		if err != nil || dayNum < 1 || dayNum > 31 {
			http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees/"+url.PathEscape(timePunchName)+"?error="+url.QueryEscape("Birthday day is invalid")+"#employee-edit", http.StatusFound)
			return
		}
		yearNum, err := strconv.Atoi(birthYear)
		if err != nil || yearNum < 1900 || yearNum > 2100 {
			http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees/"+url.PathEscape(timePunchName)+"?error="+url.QueryEscape("Birthday year is invalid")+"#employee-edit", http.StatusFound)
			return
		}
		birthday = fmt.Sprintf("%02d/%02d/%04d", monthNum, dayNum, yearNum)
	}

	payload := map[string]string{
		"firstName": strings.TrimSpace(r.FormValue("first_name")),
		"lastName":  strings.TrimSpace(r.FormValue("last_name")),
		"birthday":  birthday,
		"email":     strings.TrimSpace(r.FormValue("email")),
		"phone":     strings.TrimSpace(r.FormValue("phone")),
		"address":   strings.TrimSpace(r.FormValue("address")),
		"aptNumber": strings.TrimSpace(r.FormValue("apt_number")),
		"city":      strings.TrimSpace(r.FormValue("city")),
		"state":     strings.TrimSpace(r.FormValue("state")),
		"zipCode":   strings.TrimSpace(r.FormValue("zip_code")),
		"payType":   strings.TrimSpace(r.FormValue("pay_type")),
		"payAmount": strings.TrimSpace(r.FormValue("pay_amount")),
	}

	body, err := json.Marshal(payload)
	if err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees/"+url.PathEscape(timePunchName)+"?error="+url.QueryEscape("Unable to prepare employee update")+"#employee-edit", http.StatusFound)
		return
	}

	apiURL := s.apiBaseURL + "/api/admin/locations/" + url.PathEscape(locationNumber) + "/employees/" + url.PathEscape(timePunchName) + "/details"
	apiReq, err := http.NewRequestWithContext(r.Context(), http.MethodPut, apiURL, bytes.NewReader(body))
	if err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees/"+url.PathEscape(timePunchName)+"?error="+url.QueryEscape("Unable to update employee")+"#employee-edit", http.StatusFound)
		return
	}
	copySessionCookieHeader(r, apiReq)
	apiReq.Header.Set("Content-Type", "application/json")
	apiReq.Header.Set(csrfHeaderName, csrfToken)

	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees/"+url.PathEscape(timePunchName)+"?error="+url.QueryEscape("Service unavailable")+"#employee-edit", http.StatusFound)
		return
	}
	defer apiResp.Body.Close()
	respBody, _ := io.ReadAll(apiResp.Body)
	if apiResp.StatusCode != http.StatusOK {
		msg := "unable to update employee"
		var response map[string]string
		if err := json.Unmarshal(respBody, &response); err == nil && strings.TrimSpace(response["error"]) != "" {
			msg = response["error"]
		}
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees/"+url.PathEscape(timePunchName)+"?error="+url.QueryEscape(msg)+"#employee-edit", http.StatusFound)
		return
	}

	http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees/"+url.PathEscape(timePunchName)+"?message="+url.QueryEscape("Employee details updated")+"#employee-edit", http.StatusFound)
}

func (s *server) loginAsEmployeeTeamMemberProxy(w http.ResponseWriter, r *http.Request, locationNumber, timePunchName string) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees/"+url.PathEscape(timePunchName)+"?error=Invalid+form+submission", http.StatusFound)
		return
	}
	csrfToken := strings.TrimSpace(r.FormValue("csrf_token"))
	if csrfToken == "" {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees/"+url.PathEscape(timePunchName)+"?error=Missing+csrf+token", http.StatusFound)
		return
	}
	payload := map[string]string{
		"locationNumber": strings.TrimSpace(locationNumber),
		"timePunchName":  strings.TrimSpace(timePunchName),
	}
	body, _ := json.Marshal(payload)
	apiReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, s.apiBaseURL+"/api/auth/team-impersonate", bytes.NewReader(body))
	if err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees/"+url.PathEscape(timePunchName)+"?error=Unable+to+start+team+session", http.StatusFound)
		return
	}
	copySessionCookieHeader(r, apiReq)
	apiReq.Header.Set("Content-Type", "application/json")
	apiReq.Header.Set(csrfHeaderName, csrfToken)
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees/"+url.PathEscape(timePunchName)+"?error=Service+unavailable", http.StatusFound)
		return
	}
	defer apiResp.Body.Close()
	respBody, _ := io.ReadAll(apiResp.Body)
	if apiResp.StatusCode != http.StatusOK {
		msg := "unable to start team member session"
		var errPayload map[string]string
		if err := json.Unmarshal(respBody, &errPayload); err == nil && strings.TrimSpace(errPayload["error"]) != "" {
			msg = errPayload["error"]
		}
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees/"+url.PathEscape(timePunchName)+"?error="+url.QueryEscape(msg), http.StatusFound)
		return
	}
	sessionValue := extractAPISessionCookieValue(apiResp)
	if strings.TrimSpace(sessionValue) == "" {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees/"+url.PathEscape(timePunchName)+"?error=Unable+to+load+team+session", http.StatusFound)
		return
	}
	setScopedSessionCookie(w, teamSessionCookie, sessionValue)
	http.Redirect(w, r, "/team?message="+url.QueryEscape("Logged in as "+timePunchName), http.StatusFound)
}

func (s *server) terminateEmployeeProxy(w http.ResponseWriter, r *http.Request, locationNumber, timePunchName string) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees/"+url.PathEscape(timePunchName)+"?error=Invalid+form+submission", http.StatusFound)
		return
	}
	csrfToken := strings.TrimSpace(r.FormValue("csrf_token"))
	if csrfToken == "" {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees/"+url.PathEscape(timePunchName)+"?error=Missing+csrf+token", http.StatusFound)
		return
	}
	apiURL := s.apiBaseURL + "/api/admin/locations/" + url.PathEscape(locationNumber) + "/employees/" + url.PathEscape(timePunchName) + "/terminate"
	apiReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, apiURL, nil)
	if err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees/"+url.PathEscape(timePunchName)+"?error=Unable+to+terminate+employee", http.StatusFound)
		return
	}
	copySessionCookieHeader(r, apiReq)
	apiReq.Header.Set(csrfHeaderName, csrfToken)
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees/"+url.PathEscape(timePunchName)+"?error=Service+unavailable", http.StatusFound)
		return
	}
	defer apiResp.Body.Close()
	respBody, _ := io.ReadAll(apiResp.Body)
	if apiResp.StatusCode != http.StatusOK {
		msg := "unable to terminate employee"
		var response map[string]string
		if err := json.Unmarshal(respBody, &response); err == nil && strings.TrimSpace(response["error"]) != "" {
			msg = response["error"]
		}
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees/"+url.PathEscape(timePunchName)+"?error="+url.QueryEscape(msg), http.StatusFound)
		return
	}
	http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees/archived?message="+url.QueryEscape("Employee terminated"), http.StatusFound)
}

func (s *server) loginAsLocationProxy(w http.ResponseWriter, r *http.Request, locationNumber string) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/settings?error=Invalid+form+submission", http.StatusFound)
		return
	}
	csrfToken := strings.TrimSpace(r.FormValue("csrf_token"))
	if csrfToken == "" {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/settings?error=Missing+csrf+token", http.StatusFound)
		return
	}
	payload := map[string]string{
		"locationNumber": strings.TrimSpace(locationNumber),
	}
	body, _ := json.Marshal(payload)
	apiReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, s.apiBaseURL+"/api/auth/restaurant-impersonate", bytes.NewReader(body))
	if err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/settings?error=Unable+to+start+location+session", http.StatusFound)
		return
	}
	copySessionCookieHeader(r, apiReq)
	apiReq.Header.Set("Content-Type", "application/json")
	apiReq.Header.Set(csrfHeaderName, csrfToken)
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/settings?error=Service+unavailable", http.StatusFound)
		return
	}
	defer apiResp.Body.Close()
	respBody, _ := io.ReadAll(apiResp.Body)
	if apiResp.StatusCode != http.StatusOK {
		msg := "unable to start location session"
		var errPayload map[string]string
		if err := json.Unmarshal(respBody, &errPayload); err == nil && strings.TrimSpace(errPayload["error"]) != "" {
			msg = errPayload["error"]
		}
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/settings?error="+url.QueryEscape(msg), http.StatusFound)
		return
	}
	sessionValue := extractAPISessionCookieValue(apiResp)
	if strings.TrimSpace(sessionValue) == "" {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/settings?error=Unable+to+load+location+session", http.StatusFound)
		return
	}
	setScopedSessionCookie(w, restaurantSessionCookie, sessionValue)
	http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"?message="+url.QueryEscape("Viewing as location portal"), http.StatusFound)
}

func (s *server) createLocationProxy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	csrfToken := strings.TrimSpace(r.Header.Get(csrfHeaderName))
	if csrfToken == "" {
		http.Error(w, `{"error":"csrf token is required"}`, http.StatusForbidden)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	apiReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, s.apiBaseURL+"/api/admin/locations", bytes.NewReader(body))
	if err != nil {
		http.Error(w, `{"error":"upstream request failed"}`, http.StatusInternalServerError)
		return
	}
	copySessionCookieHeader(r, apiReq)
	apiReq.Header.Set("Content-Type", "application/json")
	apiReq.Header.Set(csrfHeaderName, csrfToken)

	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		http.Error(w, `{"error":"upstream service unavailable"}`, http.StatusBadGateway)
		return
	}
	defer apiResp.Body.Close()

	respBody, err := io.ReadAll(apiResp.Body)
	if err != nil {
		http.Error(w, `{"error":"upstream response failed"}`, http.StatusBadGateway)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(apiResp.StatusCode)
	_, _ = w.Write(respBody)
}

func (s *server) updateLocationProxy(w http.ResponseWriter, r *http.Request) {
	locationNumber, ok := locationNumberFromAdminPath(r.URL.Path)
	if !ok {
		http.NotFound(w, r)
		return
	}

	csrfToken := strings.TrimSpace(r.Header.Get(csrfHeaderName))
	if csrfToken == "" {
		http.Error(w, `{"error":"csrf token is required"}`, http.StatusForbidden)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	apiReq, err := http.NewRequestWithContext(r.Context(), http.MethodPut, s.apiBaseURL+"/api/admin/locations/"+url.PathEscape(locationNumber), bytes.NewReader(body))
	if err != nil {
		http.Error(w, `{"error":"upstream request failed"}`, http.StatusInternalServerError)
		return
	}
	copySessionCookieHeader(r, apiReq)
	apiReq.Header.Set("Content-Type", "application/json")
	apiReq.Header.Set(csrfHeaderName, csrfToken)

	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		http.Error(w, `{"error":"upstream service unavailable"}`, http.StatusBadGateway)
		return
	}
	defer apiResp.Body.Close()

	respBody, err := io.ReadAll(apiResp.Body)
	if err != nil {
		http.Error(w, `{"error":"upstream response failed"}`, http.StatusBadGateway)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(apiResp.StatusCode)
	_, _ = w.Write(respBody)
}

func (s *server) updateLocationSettingsProxy(w http.ResponseWriter, r *http.Request, locationNumber string) {
	csrfToken := strings.TrimSpace(r.Header.Get(csrfHeaderName))
	if csrfToken == "" {
		http.Error(w, `{"error":"csrf token is required"}`, http.StatusForbidden)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}
	apiReq, err := http.NewRequestWithContext(r.Context(), http.MethodPut, s.apiBaseURL+"/api/admin/locations/"+url.PathEscape(locationNumber)+"/settings", bytes.NewReader(body))
	if err != nil {
		http.Error(w, `{"error":"upstream request failed"}`, http.StatusInternalServerError)
		return
	}
	copySessionCookieHeader(r, apiReq)
	apiReq.Header.Set("Content-Type", "application/json")
	apiReq.Header.Set(csrfHeaderName, csrfToken)

	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		http.Error(w, `{"error":"upstream service unavailable"}`, http.StatusBadGateway)
		return
	}
	defer apiResp.Body.Close()
	respBody, err := io.ReadAll(apiResp.Body)
	if err != nil {
		http.Error(w, `{"error":"upstream response failed"}`, http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(apiResp.StatusCode)
	_, _ = w.Write(respBody)
}

func (s *server) deleteLocationProxy(w http.ResponseWriter, r *http.Request) {
	currentUser, err := s.fetchSessionUserByRoles(r, []string{"admin"})
	if err != nil || currentUser == nil {
		http.Error(w, `{"error":"admin access required"}`, http.StatusForbidden)
		return
	}

	locationNumber, ok := locationNumberFromAdminPath(r.URL.Path)
	if !ok {
		http.NotFound(w, r)
		return
	}

	csrfToken := strings.TrimSpace(r.Header.Get(csrfHeaderName))
	if csrfToken == "" {
		http.Error(w, `{"error":"csrf token is required"}`, http.StatusForbidden)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	apiReq, err := http.NewRequestWithContext(r.Context(), http.MethodDelete, s.apiBaseURL+"/api/admin/locations/"+url.PathEscape(locationNumber), bytes.NewReader(body))
	if err != nil {
		http.Error(w, `{"error":"upstream request failed"}`, http.StatusInternalServerError)
		return
	}
	copySessionCookieHeader(r, apiReq)
	apiReq.Header.Set("Content-Type", "application/json")
	apiReq.Header.Set(csrfHeaderName, csrfToken)

	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		http.Error(w, `{"error":"upstream service unavailable"}`, http.StatusBadGateway)
		return
	}
	defer apiResp.Body.Close()

	respBody, err := io.ReadAll(apiResp.Body)
	if err != nil {
		http.Error(w, `{"error":"upstream response failed"}`, http.StatusBadGateway)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(apiResp.StatusCode)
	_, _ = w.Write(respBody)
}

func (s *server) updateEmployeeDepartmentProxy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	trimmed := strings.TrimPrefix(r.URL.Path, "/admin/locations/")
	trimmed = strings.Trim(trimmed, "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) != 4 || parts[1] != "employees" || parts[3] != "department" {
		http.NotFound(w, r)
		return
	}
	locationNumber, err := url.PathUnescape(parts[0])
	if err != nil || strings.TrimSpace(locationNumber) == "" {
		http.NotFound(w, r)
		return
	}
	timePunchName, err := url.PathUnescape(parts[2])
	if err != nil || strings.TrimSpace(timePunchName) == "" {
		http.NotFound(w, r)
		return
	}

	csrfToken := strings.TrimSpace(r.Header.Get(csrfHeaderName))
	if csrfToken == "" {
		http.Error(w, `{"error":"csrf token is required"}`, http.StatusForbidden)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	apiURL := s.apiBaseURL + "/api/admin/locations/" + url.PathEscape(locationNumber) + "/employees/" + url.PathEscape(timePunchName) + "/department"
	apiReq, err := http.NewRequestWithContext(r.Context(), http.MethodPut, apiURL, bytes.NewReader(body))
	if err != nil {
		http.Error(w, `{"error":"upstream request failed"}`, http.StatusInternalServerError)
		return
	}
	copySessionCookieHeader(r, apiReq)
	apiReq.Header.Set("Content-Type", "application/json")
	apiReq.Header.Set(csrfHeaderName, csrfToken)

	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		http.Error(w, `{"error":"upstream service unavailable"}`, http.StatusBadGateway)
		return
	}
	defer apiResp.Body.Close()

	respBody, err := io.ReadAll(apiResp.Body)
	if err != nil {
		http.Error(w, `{"error":"upstream response failed"}`, http.StatusBadGateway)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(apiResp.StatusCode)
	_, _ = w.Write(respBody)
}

func (s *server) updateEmployeeJobProxy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	trimmed := strings.TrimPrefix(r.URL.Path, "/admin/locations/")
	trimmed = strings.Trim(trimmed, "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) != 4 || parts[1] != "employees" || parts[3] != "job" {
		http.NotFound(w, r)
		return
	}
	locationNumber, err := url.PathUnescape(parts[0])
	if err != nil || strings.TrimSpace(locationNumber) == "" {
		http.NotFound(w, r)
		return
	}
	timePunchName, err := url.PathUnescape(parts[2])
	if err != nil || strings.TrimSpace(timePunchName) == "" {
		http.NotFound(w, r)
		return
	}

	csrfToken := strings.TrimSpace(r.Header.Get(csrfHeaderName))
	if csrfToken == "" {
		http.Error(w, `{"error":"csrf token is required"}`, http.StatusForbidden)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	apiURL := s.apiBaseURL + "/api/admin/locations/" + url.PathEscape(locationNumber) + "/employees/" + url.PathEscape(timePunchName) + "/job"
	apiReq, err := http.NewRequestWithContext(r.Context(), http.MethodPut, apiURL, bytes.NewReader(body))
	if err != nil {
		http.Error(w, `{"error":"upstream request failed"}`, http.StatusInternalServerError)
		return
	}
	copySessionCookieHeader(r, apiReq)
	apiReq.Header.Set("Content-Type", "application/json")
	apiReq.Header.Set(csrfHeaderName, csrfToken)

	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		http.Error(w, `{"error":"upstream service unavailable"}`, http.StatusBadGateway)
		return
	}
	defer apiResp.Body.Close()

	respBody, err := io.ReadAll(apiResp.Body)
	if err != nil {
		http.Error(w, `{"error":"upstream response failed"}`, http.StatusBadGateway)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(apiResp.StatusCode)
	_, _ = w.Write(respBody)
}

func (s *server) updateEmployeePayBandProxy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	trimmed := strings.TrimPrefix(r.URL.Path, "/admin/locations/")
	trimmed = strings.Trim(trimmed, "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) != 4 || parts[1] != "employees" || parts[3] != "pay-band" {
		http.NotFound(w, r)
		return
	}
	locationNumber, err := url.PathUnescape(parts[0])
	if err != nil || strings.TrimSpace(locationNumber) == "" {
		http.NotFound(w, r)
		return
	}
	timePunchName, err := url.PathUnescape(parts[2])
	if err != nil || strings.TrimSpace(timePunchName) == "" {
		http.NotFound(w, r)
		return
	}
	csrfToken := strings.TrimSpace(r.Header.Get(csrfHeaderName))
	if csrfToken == "" {
		http.Error(w, `{"error":"csrf token is required"}`, http.StatusForbidden)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}
	apiURL := s.apiBaseURL + "/api/admin/locations/" + url.PathEscape(locationNumber) + "/employees/" + url.PathEscape(timePunchName) + "/pay-band"
	apiReq, err := http.NewRequestWithContext(r.Context(), http.MethodPut, apiURL, bytes.NewReader(body))
	if err != nil {
		http.Error(w, `{"error":"upstream request failed"}`, http.StatusInternalServerError)
		return
	}
	copySessionCookieHeader(r, apiReq)
	apiReq.Header.Set("Content-Type", "application/json")
	apiReq.Header.Set(csrfHeaderName, csrfToken)
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		http.Error(w, `{"error":"upstream service unavailable"}`, http.StatusBadGateway)
		return
	}
	defer apiResp.Body.Close()
	respBody, err := io.ReadAll(apiResp.Body)
	if err != nil {
		http.Error(w, `{"error":"upstream response failed"}`, http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(apiResp.StatusCode)
	_, _ = w.Write(respBody)
}

func (s *server) employeeAdditionalCompensationProxy(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.NotFound(w, r)
		return
	}
	csrfToken := strings.TrimSpace(r.FormValue("csrf_token"))
	if csrfToken == "" {
		http.NotFound(w, r)
		return
	}
	trimmed := strings.TrimPrefix(r.URL.Path, "/admin/locations/")
	trimmed = strings.Trim(trimmed, "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) < 6 || parts[1] != "employees" || parts[3] != "additional-compensations" {
		http.NotFound(w, r)
		return
	}
	locationNumber, err := url.PathUnescape(parts[0])
	if err != nil || strings.TrimSpace(locationNumber) == "" {
		http.NotFound(w, r)
		return
	}
	timePunchName, err := url.PathUnescape(parts[2])
	if err != nil || strings.TrimSpace(timePunchName) == "" {
		http.NotFound(w, r)
		return
	}
	redirectPath := "/admin/locations/" + url.PathEscape(locationNumber) + "/employees/" + url.PathEscape(timePunchName) + "#profile"

	if len(parts) == 6 && parts[4] == "add" && parts[5] == "create" {
		payload := map[string]string{
			"label":  strings.TrimSpace(r.FormValue("label")),
			"amount": strings.TrimSpace(r.FormValue("amount")),
		}
		body, _ := json.Marshal(payload)
		apiReq, err := http.NewRequestWithContext(
			r.Context(),
			http.MethodPost,
			s.apiBaseURL+"/api/admin/locations/"+url.PathEscape(locationNumber)+"/employees/"+url.PathEscape(timePunchName)+"/additional-compensations/add",
			bytes.NewReader(body),
		)
		if err != nil {
			http.Redirect(w, r, redirectPath+"?error=Unable+to+add+compensation", http.StatusFound)
			return
		}
		copySessionCookieHeader(r, apiReq)
		apiReq.Header.Set("Content-Type", "application/json")
		apiReq.Header.Set(csrfHeaderName, csrfToken)
		apiResp, err := s.apiClient.Do(apiReq)
		if err != nil {
			http.Redirect(w, r, redirectPath+"?error=Service+unavailable", http.StatusFound)
			return
		}
		defer apiResp.Body.Close()
		respBody, _ := io.ReadAll(apiResp.Body)
		if apiResp.StatusCode != http.StatusCreated && apiResp.StatusCode != http.StatusOK {
			msg := "unable to add compensation"
			var errPayload map[string]string
			if err := json.Unmarshal(respBody, &errPayload); err == nil && strings.TrimSpace(errPayload["error"]) != "" {
				msg = errPayload["error"]
			}
			http.Redirect(w, r, redirectPath+"?error="+url.QueryEscape(msg), http.StatusFound)
			return
		}
		http.Redirect(w, r, redirectPath+"?message="+url.QueryEscape("Additional compensation added"), http.StatusFound)
		return
	}

	if len(parts) == 6 && parts[5] == "delete" {
		compID, err := strconv.ParseInt(strings.TrimSpace(parts[4]), 10, 64)
		if err != nil || compID <= 0 {
			http.Redirect(w, r, redirectPath+"?error=Invalid+compensation+id", http.StatusFound)
			return
		}
		apiReq, err := http.NewRequestWithContext(
			r.Context(),
			http.MethodDelete,
			s.apiBaseURL+"/api/admin/locations/"+url.PathEscape(locationNumber)+"/employees/"+url.PathEscape(timePunchName)+"/additional-compensations/"+strconv.FormatInt(compID, 10)+"/delete",
			nil,
		)
		if err != nil {
			http.Redirect(w, r, redirectPath+"?error=Unable+to+delete+compensation", http.StatusFound)
			return
		}
		copySessionCookieHeader(r, apiReq)
		apiReq.Header.Set(csrfHeaderName, csrfToken)
		apiResp, err := s.apiClient.Do(apiReq)
		if err != nil {
			http.Redirect(w, r, redirectPath+"?error=Service+unavailable", http.StatusFound)
			return
		}
		defer apiResp.Body.Close()
		respBody, _ := io.ReadAll(apiResp.Body)
		if apiResp.StatusCode != http.StatusOK {
			msg := "unable to delete compensation"
			var errPayload map[string]string
			if err := json.Unmarshal(respBody, &errPayload); err == nil && strings.TrimSpace(errPayload["error"]) != "" {
				msg = errPayload["error"]
			}
			http.Redirect(w, r, redirectPath+"?error="+url.QueryEscape(msg), http.StatusFound)
			return
		}
		http.Redirect(w, r, redirectPath+"?message="+url.QueryEscape("Additional compensation deleted"), http.StatusFound)
		return
	}

	http.NotFound(w, r)
}

func (s *server) updateEmployeeClockInPINProxy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	trimmed := strings.TrimPrefix(r.URL.Path, "/admin/locations/")
	trimmed = strings.Trim(trimmed, "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) != 4 || parts[1] != "employees" || parts[3] != "clock-in-pin" {
		http.NotFound(w, r)
		return
	}
	locationNumber, err := url.PathUnescape(parts[0])
	if err != nil || strings.TrimSpace(locationNumber) == "" {
		http.NotFound(w, r)
		return
	}
	timePunchName, err := url.PathUnescape(parts[2])
	if err != nil || strings.TrimSpace(timePunchName) == "" {
		http.NotFound(w, r)
		return
	}
	csrfToken := strings.TrimSpace(r.Header.Get(csrfHeaderName))
	if csrfToken == "" {
		http.Error(w, `{"error":"csrf token is required"}`, http.StatusForbidden)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}
	apiURL := s.apiBaseURL + "/api/admin/locations/" + url.PathEscape(locationNumber) + "/employees/" + url.PathEscape(timePunchName) + "/clock-in-pin"
	apiReq, err := http.NewRequestWithContext(r.Context(), http.MethodPut, apiURL, bytes.NewReader(body))
	if err != nil {
		http.Error(w, `{"error":"upstream request failed"}`, http.StatusInternalServerError)
		return
	}
	copySessionCookieHeader(r, apiReq)
	apiReq.Header.Set("Content-Type", "application/json")
	apiReq.Header.Set(csrfHeaderName, csrfToken)
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		http.Error(w, `{"error":"upstream service unavailable"}`, http.StatusBadGateway)
		return
	}
	defer apiResp.Body.Close()
	respBody, err := io.ReadAll(apiResp.Body)
	if err != nil {
		http.Error(w, `{"error":"upstream response failed"}`, http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(apiResp.StatusCode)
	_, _ = w.Write(respBody)
}

func (s *server) getEmployeePhotoProxy(w http.ResponseWriter, r *http.Request) {
	locationNumber, timePunchName, ok := parseLocationEmployeeActionPath(r.URL.Path, "photo")
	if !ok {
		http.NotFound(w, r)
		return
	}
	apiURL := s.apiBaseURL + "/api/admin/locations/" + url.PathEscape(locationNumber) + "/employees/" + url.PathEscape(timePunchName) + "/photo"
	apiReq, err := http.NewRequestWithContext(r.Context(), http.MethodGet, apiURL, nil)
	if err != nil {
		http.Error(w, "upstream request failed", http.StatusInternalServerError)
		return
	}
	copySessionCookieHeader(r, apiReq)
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		http.Error(w, "upstream service unavailable", http.StatusBadGateway)
		return
	}
	defer apiResp.Body.Close()
	if apiResp.StatusCode != http.StatusOK {
		http.NotFound(w, r)
		return
	}
	if ct := apiResp.Header.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	_, _ = io.Copy(w, apiResp.Body)
}

func (s *server) uploadEmployeePhotoProxy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	locationNumber, timePunchName, ok := parseLocationEmployeeActionPath(r.URL.Path, "photo")
	if !ok {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseMultipartForm(20 << 20); err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees/"+url.PathEscape(timePunchName)+"?error=Invalid+upload", http.StatusFound)
		return
	}
	csrfToken := strings.TrimSpace(r.FormValue("csrf_token"))
	if csrfToken == "" {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees/"+url.PathEscape(timePunchName)+"?error=Missing+csrf+token", http.StatusFound)
		return
	}
	file, header, err := r.FormFile("photo_file")
	if err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees/"+url.PathEscape(timePunchName)+"?error=Photo+file+is+required", http.StatusFound)
		return
	}
	defer file.Close()

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("photo_file", header.Filename)
	if err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees/"+url.PathEscape(timePunchName)+"?error=Unable+to+prepare+upload", http.StatusFound)
		return
	}
	if _, err := io.Copy(part, file); err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees/"+url.PathEscape(timePunchName)+"?error=Unable+to+read+upload", http.StatusFound)
		return
	}
	for _, key := range []string{"crop_x", "crop_y", "crop_size"} {
		if value := strings.TrimSpace(r.FormValue(key)); value != "" {
			_ = writer.WriteField(key, value)
		}
	}
	if err := writer.Close(); err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees/"+url.PathEscape(timePunchName)+"?error=Unable+to+finalize+upload", http.StatusFound)
		return
	}

	apiURL := s.apiBaseURL + "/api/admin/locations/" + url.PathEscape(locationNumber) + "/employees/" + url.PathEscape(timePunchName) + "/photo"
	apiReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, apiURL, &body)
	if err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees/"+url.PathEscape(timePunchName)+"?error=Unable+to+send+upload", http.StatusFound)
		return
	}
	copySessionCookieHeader(r, apiReq)
	apiReq.Header.Set("Content-Type", writer.FormDataContentType())
	apiReq.Header.Set(csrfHeaderName, csrfToken)

	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees/"+url.PathEscape(timePunchName)+"?error=Upload+service+unavailable", http.StatusFound)
		return
	}
	defer apiResp.Body.Close()
	respBody, _ := io.ReadAll(apiResp.Body)
	if apiResp.StatusCode != http.StatusOK {
		msg := "unable to upload photo"
		var payload map[string]string
		if err := json.Unmarshal(respBody, &payload); err == nil && payload["error"] != "" {
			msg = payload["error"]
		}
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees/"+url.PathEscape(timePunchName)+"?error="+url.QueryEscape(msg), http.StatusFound)
		return
	}
	http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees/"+url.PathEscape(timePunchName)+"?message="+url.QueryEscape("Photo uploaded"), http.StatusFound)
}

func (s *server) createEmployeePhotoLinkProxy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	locationNumber, timePunchName, ok := parseLocationEmployeeActionPath(r.URL.Path, "photo-link")
	if !ok {
		http.NotFound(w, r)
		return
	}
	csrfToken := strings.TrimSpace(r.Header.Get(csrfHeaderName))
	if csrfToken == "" {
		http.Error(w, `{"error":"csrf token is required"}`, http.StatusForbidden)
		return
	}
	apiURL := s.apiBaseURL + "/api/admin/locations/" + url.PathEscape(locationNumber) + "/employees/" + url.PathEscape(timePunchName) + "/photo-link"
	apiReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, apiURL, bytes.NewReader([]byte(`{}`)))
	if err != nil {
		http.Error(w, `{"error":"upstream request failed"}`, http.StatusInternalServerError)
		return
	}
	copySessionCookieHeader(r, apiReq)
	apiReq.Header.Set("Content-Type", "application/json")
	apiReq.Header.Set(csrfHeaderName, csrfToken)

	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		http.Error(w, `{"error":"upstream service unavailable"}`, http.StatusBadGateway)
		return
	}
	defer apiResp.Body.Close()
	var payload photoLinkResponse
	if apiResp.StatusCode == http.StatusOK {
		if err := json.NewDecoder(apiResp.Body).Decode(&payload); err != nil {
			http.Error(w, `{"error":"invalid upstream response"}`, http.StatusBadGateway)
			return
		}
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		link := scheme + "://" + r.Host + "/employee/photo-upload/" + url.PathEscape(payload.Token)
		writeJSON(w, http.StatusOK, map[string]string{
			"uploadLink": link,
			"expiresAt":  payload.ExpiresAt,
		})
		return
	}
	respBody, _ := io.ReadAll(apiResp.Body)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(apiResp.StatusCode)
	_, _ = w.Write(respBody)
}

func (s *server) createEmployeePaperworkLinkProxy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	locationNumber, timePunchName, ok := parseLocationEmployeeActionPath(r.URL.Path, "paperwork-link")
	if !ok {
		http.NotFound(w, r)
		return
	}
	csrfToken := strings.TrimSpace(r.Header.Get(csrfHeaderName))
	if csrfToken == "" {
		http.Error(w, `{"error":"csrf token is required"}`, http.StatusForbidden)
		return
	}
	apiURL := s.apiBaseURL + "/api/admin/locations/" + url.PathEscape(locationNumber) + "/employees/" + url.PathEscape(timePunchName) + "/paperwork-link"
	apiReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, apiURL, bytes.NewReader([]byte(`{}`)))
	if err != nil {
		http.Error(w, `{"error":"upstream request failed"}`, http.StatusInternalServerError)
		return
	}
	copySessionCookieHeader(r, apiReq)
	apiReq.Header.Set("Content-Type", "application/json")
	apiReq.Header.Set(csrfHeaderName, csrfToken)

	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		http.Error(w, `{"error":"upstream service unavailable"}`, http.StatusBadGateway)
		return
	}
	defer apiResp.Body.Close()
	var payload photoLinkResponse
	if apiResp.StatusCode == http.StatusOK {
		if err := json.NewDecoder(apiResp.Body).Decode(&payload); err != nil {
			http.Error(w, `{"error":"invalid upstream response"}`, http.StatusBadGateway)
			return
		}
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		link := scheme + "://" + r.Host + "/employee/paperwork/" + url.PathEscape(payload.Token)
		writeJSON(w, http.StatusOK, map[string]string{
			"uploadLink": link,
			"expiresAt":  payload.ExpiresAt,
		})
		return
	}
	respBody, _ := io.ReadAll(apiResp.Body)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(apiResp.StatusCode)
	_, _ = w.Write(respBody)
}

func (s *server) getEmployeeI9FileProxy(w http.ResponseWriter, r *http.Request) {
	apiPath, ok := mapEmployeeI9FilePathToAPI(r.URL.Path)
	if !ok {
		http.NotFound(w, r)
		return
	}
	apiURL := s.apiBaseURL + apiPath
	if strings.TrimSpace(r.URL.RawQuery) != "" {
		apiURL += "?" + r.URL.RawQuery
	}
	apiReq, err := http.NewRequestWithContext(r.Context(), http.MethodGet, apiURL, nil)
	if err != nil {
		http.Error(w, "upstream request failed", http.StatusInternalServerError)
		return
	}
	copySessionCookieHeader(r, apiReq)
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		http.Error(w, "upstream service unavailable", http.StatusBadGateway)
		return
	}
	defer apiResp.Body.Close()
	if apiResp.StatusCode != http.StatusOK {
		http.NotFound(w, r)
		return
	}
	if ct := apiResp.Header.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	if cd := apiResp.Header.Get("Content-Disposition"); cd != "" {
		w.Header().Set("Content-Disposition", cd)
	}
	_, _ = io.Copy(w, apiResp.Body)
}

func (s *server) getEmployeeW4FileProxy(w http.ResponseWriter, r *http.Request) {
	apiPath, ok := mapEmployeeW4FilePathToAPI(r.URL.Path)
	if !ok {
		http.NotFound(w, r)
		return
	}
	apiURL := s.apiBaseURL + apiPath
	if strings.TrimSpace(r.URL.RawQuery) != "" {
		apiURL += "?" + r.URL.RawQuery
	}
	apiReq, err := http.NewRequestWithContext(r.Context(), http.MethodGet, apiURL, nil)
	if err != nil {
		http.Error(w, "upstream request failed", http.StatusInternalServerError)
		return
	}
	copySessionCookieHeader(r, apiReq)
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		http.Error(w, "upstream service unavailable", http.StatusBadGateway)
		return
	}
	defer apiResp.Body.Close()
	if apiResp.StatusCode != http.StatusOK {
		http.NotFound(w, r)
		return
	}
	if ct := apiResp.Header.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	if cd := apiResp.Header.Get("Content-Disposition"); cd != "" {
		w.Header().Set("Content-Disposition", cd)
	}
	_, _ = io.Copy(w, apiResp.Body)
}

func (s *server) getEmployeeI9DocumentFileProxy(w http.ResponseWriter, r *http.Request) {
	apiPath, ok := mapEmployeeI9DocumentFilePathToAPI(r.URL.Path)
	if !ok {
		http.NotFound(w, r)
		return
	}
	apiReq, err := http.NewRequestWithContext(r.Context(), http.MethodGet, s.apiBaseURL+apiPath, nil)
	if err != nil {
		http.Error(w, "upstream request failed", http.StatusInternalServerError)
		return
	}
	copySessionCookieHeader(r, apiReq)
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		http.Error(w, "upstream service unavailable", http.StatusBadGateway)
		return
	}
	defer apiResp.Body.Close()
	if apiResp.StatusCode != http.StatusOK {
		http.NotFound(w, r)
		return
	}
	if ct := apiResp.Header.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	if cd := apiResp.Header.Get("Content-Disposition"); cd != "" {
		w.Header().Set("Content-Disposition", cd)
	}
	_, _ = io.Copy(w, apiResp.Body)
}

func (s *server) uploadEmployeeI9Proxy(w http.ResponseWriter, r *http.Request, locationNumber, timePunchName string) {
	basePath := "/admin/locations/" + url.PathEscape(locationNumber) + "/employees/" + url.PathEscape(timePunchName)
	if err := r.ParseMultipartForm(20 << 20); err != nil {
		http.Redirect(w, r, basePath+"?error=Invalid+upload#paperwork-upload", http.StatusFound)
		return
	}
	csrfToken := strings.TrimSpace(r.FormValue("csrf_token"))
	if csrfToken == "" {
		http.Redirect(w, r, basePath+"?error=Missing+csrf+token#paperwork-upload", http.StatusFound)
		return
	}
	file, header, err := r.FormFile("i9_file")
	if err != nil {
		http.Redirect(w, r, basePath+"?error=I-9+file+is+required#paperwork-upload", http.StatusFound)
		return
	}
	defer file.Close()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("i9_file", header.Filename)
	if err != nil {
		http.Redirect(w, r, basePath+"?error=Unable+to+prepare+upload#paperwork-upload", http.StatusFound)
		return
	}
	if _, err := io.Copy(part, file); err != nil {
		http.Redirect(w, r, basePath+"?error=Unable+to+read+upload#paperwork-upload", http.StatusFound)
		return
	}
	if err := writer.Close(); err != nil {
		http.Redirect(w, r, basePath+"?error=Unable+to+finalize+upload#paperwork-upload", http.StatusFound)
		return
	}
	apiURL := s.apiBaseURL + "/api/admin/locations/" + url.PathEscape(locationNumber) + "/employees/" + url.PathEscape(timePunchName) + "/i9"
	apiReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, apiURL, &body)
	if err != nil {
		http.Redirect(w, r, basePath+"?error=Unable+to+send+upload#paperwork-upload", http.StatusFound)
		return
	}
	copySessionCookieHeader(r, apiReq)
	apiReq.Header.Set("Content-Type", writer.FormDataContentType())
	apiReq.Header.Set(csrfHeaderName, csrfToken)
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		http.Redirect(w, r, basePath+"?error=Service+unavailable#paperwork-upload", http.StatusFound)
		return
	}
	defer apiResp.Body.Close()
	respBody, _ := io.ReadAll(apiResp.Body)
	if apiResp.StatusCode != http.StatusOK {
		msg := "unable to save i9"
		var payload map[string]string
		if err := json.Unmarshal(respBody, &payload); err == nil && strings.TrimSpace(payload["error"]) != "" {
			msg = payload["error"]
		}
		http.Redirect(w, r, basePath+"?error="+url.QueryEscape(msg)+"#paperwork-upload", http.StatusFound)
		return
	}
	http.Redirect(w, r, basePath+"?message="+url.QueryEscape("I-9 uploaded")+"&saved=i9#paperwork-upload", http.StatusFound)
}

func (s *server) uploadEmployeeW4Proxy(w http.ResponseWriter, r *http.Request, locationNumber, timePunchName string) {
	basePath := "/admin/locations/" + url.PathEscape(locationNumber) + "/employees/" + url.PathEscape(timePunchName)
	if err := r.ParseMultipartForm(20 << 20); err != nil {
		http.Redirect(w, r, basePath+"?error=Invalid+upload#paperwork-upload", http.StatusFound)
		return
	}
	csrfToken := strings.TrimSpace(r.FormValue("csrf_token"))
	if csrfToken == "" {
		http.Redirect(w, r, basePath+"?error=Missing+csrf+token#paperwork-upload", http.StatusFound)
		return
	}
	file, header, err := r.FormFile("w4_file")
	if err != nil {
		http.Redirect(w, r, basePath+"?error=W-4+file+is+required#paperwork-upload", http.StatusFound)
		return
	}
	defer file.Close()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("w4_file", header.Filename)
	if err != nil {
		http.Redirect(w, r, basePath+"?error=Unable+to+prepare+upload#paperwork-upload", http.StatusFound)
		return
	}
	if _, err := io.Copy(part, file); err != nil {
		http.Redirect(w, r, basePath+"?error=Unable+to+read+upload#paperwork-upload", http.StatusFound)
		return
	}
	if err := writer.Close(); err != nil {
		http.Redirect(w, r, basePath+"?error=Unable+to+finalize+upload#paperwork-upload", http.StatusFound)
		return
	}
	apiURL := s.apiBaseURL + "/api/admin/locations/" + url.PathEscape(locationNumber) + "/employees/" + url.PathEscape(timePunchName) + "/w4"
	apiReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, apiURL, &body)
	if err != nil {
		http.Redirect(w, r, basePath+"?error=Unable+to+send+upload#paperwork-upload", http.StatusFound)
		return
	}
	copySessionCookieHeader(r, apiReq)
	apiReq.Header.Set("Content-Type", writer.FormDataContentType())
	apiReq.Header.Set(csrfHeaderName, csrfToken)
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		http.Redirect(w, r, basePath+"?error=Service+unavailable#paperwork-upload", http.StatusFound)
		return
	}
	defer apiResp.Body.Close()
	respBody, _ := io.ReadAll(apiResp.Body)
	if apiResp.StatusCode != http.StatusOK {
		msg := "unable to save w4"
		var payload map[string]string
		if err := json.Unmarshal(respBody, &payload); err == nil && strings.TrimSpace(payload["error"]) != "" {
			msg = payload["error"]
		}
		http.Redirect(w, r, basePath+"?error="+url.QueryEscape(msg)+"#paperwork-upload", http.StatusFound)
		return
	}
	http.Redirect(w, r, basePath+"?message="+url.QueryEscape("W-4 uploaded")+"&saved=w4#paperwork-upload", http.StatusFound)
}

func (s *server) uploadEmployeeI9DocumentProxy(w http.ResponseWriter, r *http.Request, locationNumber, timePunchName string) {
	basePath := "/admin/locations/" + url.PathEscape(locationNumber) + "/employees/" + url.PathEscape(timePunchName)
	if err := r.ParseMultipartForm(20 << 20); err != nil {
		http.Redirect(w, r, basePath+"?error=Invalid+upload#paperwork-upload", http.StatusFound)
		return
	}
	csrfToken := strings.TrimSpace(r.FormValue("csrf_token"))
	if csrfToken == "" {
		http.Redirect(w, r, basePath+"?error=Missing+csrf+token#paperwork-upload", http.StatusFound)
		return
	}
	file, header, err := r.FormFile("document_file")
	if err != nil {
		http.Redirect(w, r, basePath+"?error=Document+file+is+required#paperwork-upload", http.StatusFound)
		return
	}
	defer file.Close()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("document_file", header.Filename)
	if err != nil {
		http.Redirect(w, r, basePath+"?error=Unable+to+prepare+upload#paperwork-upload", http.StatusFound)
		return
	}
	if _, err := io.Copy(part, file); err != nil {
		http.Redirect(w, r, basePath+"?error=Unable+to+read+upload#paperwork-upload", http.StatusFound)
		return
	}
	if v := strings.TrimSpace(r.FormValue("list_type")); v != "" {
		_ = writer.WriteField("list_type", v)
	}
	if v := strings.TrimSpace(r.FormValue("document_title")); v != "" {
		_ = writer.WriteField("document_title", v)
	}
	if err := writer.Close(); err != nil {
		http.Redirect(w, r, basePath+"?error=Unable+to+finalize+upload#paperwork-upload", http.StatusFound)
		return
	}
	apiURL := s.apiBaseURL + "/api/admin/locations/" + url.PathEscape(locationNumber) + "/employees/" + url.PathEscape(timePunchName) + "/i9/documents"
	apiReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, apiURL, &body)
	if err != nil {
		http.Redirect(w, r, basePath+"?error=Unable+to+send+upload#paperwork-upload", http.StatusFound)
		return
	}
	copySessionCookieHeader(r, apiReq)
	apiReq.Header.Set("Content-Type", writer.FormDataContentType())
	apiReq.Header.Set(csrfHeaderName, csrfToken)
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		http.Redirect(w, r, basePath+"?error=Service+unavailable#paperwork-upload", http.StatusFound)
		return
	}
	defer apiResp.Body.Close()
	respBody, _ := io.ReadAll(apiResp.Body)
	if apiResp.StatusCode != http.StatusCreated && apiResp.StatusCode != http.StatusOK {
		msg := "unable to save i9 document"
		var payload map[string]string
		if err := json.Unmarshal(respBody, &payload); err == nil && strings.TrimSpace(payload["error"]) != "" {
			msg = payload["error"]
		}
		http.Redirect(w, r, basePath+"?error="+url.QueryEscape(msg)+"#paperwork-upload", http.StatusFound)
		return
	}
	http.Redirect(w, r, basePath+"?message="+url.QueryEscape("Supporting document uploaded")+"&saved=other#paperwork-upload", http.StatusFound)
}

func (s *server) deleteEmployeeI9DocumentProxy(w http.ResponseWriter, r *http.Request, locationNumber, timePunchName string, docID int64) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees/"+url.PathEscape(timePunchName)+"?error=Invalid+form+submission", http.StatusFound)
		return
	}
	csrfToken := strings.TrimSpace(r.FormValue("csrf_token"))
	if csrfToken == "" {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees/"+url.PathEscape(timePunchName)+"?error=Missing+csrf+token", http.StatusFound)
		return
	}
	apiURL := s.apiBaseURL + "/api/admin/locations/" + url.PathEscape(locationNumber) + "/employees/" + url.PathEscape(timePunchName) + "/i9/documents/" + strconv.FormatInt(docID, 10)
	apiReq, err := http.NewRequestWithContext(r.Context(), http.MethodDelete, apiURL, nil)
	if err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees/"+url.PathEscape(timePunchName)+"?error=Unable+to+delete+document", http.StatusFound)
		return
	}
	copySessionCookieHeader(r, apiReq)
	apiReq.Header.Set(csrfHeaderName, csrfToken)
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees/"+url.PathEscape(timePunchName)+"?error=Service+unavailable", http.StatusFound)
		return
	}
	defer apiResp.Body.Close()
	respBody, _ := io.ReadAll(apiResp.Body)
	if apiResp.StatusCode != http.StatusOK {
		msg := "unable to delete i9 document"
		var payload map[string]string
		if err := json.Unmarshal(respBody, &payload); err == nil && strings.TrimSpace(payload["error"]) != "" {
			msg = payload["error"]
		}
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees/"+url.PathEscape(timePunchName)+"?error="+url.QueryEscape(msg), http.StatusFound)
		return
	}
	http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees/"+url.PathEscape(timePunchName)+"?message="+url.QueryEscape("I-9 document deleted"), http.StatusFound)
}

func (s *server) publicPhotoUploadPage(w http.ResponseWriter, r *http.Request, token string) {
	apiURL := s.apiBaseURL + "/api/public/employee-photo-upload/" + url.PathEscape(token)
	apiReq, err := http.NewRequestWithContext(r.Context(), http.MethodGet, apiURL, nil)
	if err != nil {
		http.Error(w, "request failed", http.StatusInternalServerError)
		return
	}
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		http.Error(w, "service unavailable", http.StatusBadGateway)
		return
	}
	defer apiResp.Body.Close()
	if apiResp.StatusCode == http.StatusGone {
		s.renderPublicPhotoUploadClosedPage(w, r)
		return
	}
	if apiResp.StatusCode != http.StatusOK {
		if shouldRenderPhotoUploadSubmittedFromQuery(r) {
			s.renderPublicPhotoUploadClosedPage(w, r)
			return
		}
		http.NotFound(w, r)
		return
	}
	var payload publicPhotoTokenResponse
	if err := json.NewDecoder(apiResp.Body).Decode(&payload); err != nil {
		http.Error(w, "invalid response", http.StatusBadGateway)
		return
	}
	if err := renderHTMLTemplate(w, s.publicUploadTmpl, pageData{
		Token:          token,
		Location:       &locationView{Number: payload.LocationNumber},
		Employee:       &employeeView{TimePunchName: payload.TimePunchName},
		SuccessMessage: r.URL.Query().Get("message"),
		Error:          r.URL.Query().Get("error"),
	}); err != nil {
		http.Error(w, "template render failed", http.StatusInternalServerError)
		log.Printf("public photo upload template render failed: %v", err)
	}
}

func (s *server) publicEmployeePaperworkPage(w http.ResponseWriter, r *http.Request, pathTail string) {
	apiURL := s.apiBaseURL + "/api/public/employee-paperwork/" + encodePathTail(pathTail)
	apiReq, err := http.NewRequestWithContext(r.Context(), http.MethodGet, apiURL, nil)
	if err != nil {
		http.Error(w, "request failed", http.StatusInternalServerError)
		return
	}
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		http.Error(w, "service unavailable", http.StatusBadGateway)
		return
	}
	defer apiResp.Body.Close()
	if apiResp.StatusCode == http.StatusGone {
		s.renderPublicPaperworkClosedPage(w, r)
		return
	}
	if apiResp.StatusCode != http.StatusOK {
		http.NotFound(w, r)
		return
	}
	var payload publicPaperworkTokenResponse
	if err := json.NewDecoder(apiResp.Body).Decode(&payload); err != nil {
		http.Error(w, "invalid response", http.StatusBadGateway)
		return
	}
	if err := renderHTMLTemplate(w, s.publicPaperworkTmpl, pageData{
		Token: encodePathTail(pathTail),
		Location: &locationView{
			Number: payload.LocationNumber,
			Name:   payload.LocationName,
		},
		Employee: &employeeView{
			TimePunchName: payload.TimePunchName,
			FirstName:     payload.FirstName,
			LastName:      payload.LastName,
		},
		SuccessMessage: r.URL.Query().Get("message"),
		Error:          r.URL.Query().Get("error"),
	}); err != nil {
		http.Error(w, "template render failed", http.StatusInternalServerError)
		log.Printf("public employee paperwork template render failed: %v", err)
	}
}

func (s *server) publicEmployeePaperworkSubmit(w http.ResponseWriter, r *http.Request, pathTail string) {
	apiURL := s.apiBaseURL + "/api/public/employee-paperwork/" + encodePathTail(pathTail)
	contentType := strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Type")))

	var (
		apiReq *http.Request
		err    error
	)
	if strings.HasPrefix(contentType, "multipart/form-data") {
		if err := r.ParseMultipartForm(36 << 20); err != nil {
			http.Redirect(w, r, "/employee/paperwork/"+encodePathTail(pathTail)+"?error=Invalid+form+submission", http.StatusFound)
			return
		}
		var body bytes.Buffer
		writer := multipart.NewWriter(&body)
		if r.MultipartForm != nil {
			for key, items := range r.MultipartForm.Value {
				for _, item := range items {
					_ = writer.WriteField(key, strings.TrimSpace(item))
				}
			}
			for key, files := range r.MultipartForm.File {
				for _, header := range files {
					if header == nil {
						continue
					}
					src, openErr := header.Open()
					if openErr != nil {
						_ = writer.Close()
						http.Redirect(w, r, "/employee/paperwork/"+encodePathTail(pathTail)+"?error=Unable+to+read+uploaded+document", http.StatusFound)
						return
					}
					part, createErr := writer.CreateFormFile(key, header.Filename)
					if createErr != nil {
						_ = src.Close()
						_ = writer.Close()
						http.Redirect(w, r, "/employee/paperwork/"+encodePathTail(pathTail)+"?error=Unable+to+prepare+uploaded+document", http.StatusFound)
						return
					}
					if _, copyErr := io.Copy(part, src); copyErr != nil {
						_ = src.Close()
						_ = writer.Close()
						http.Redirect(w, r, "/employee/paperwork/"+encodePathTail(pathTail)+"?error=Unable+to+read+uploaded+document", http.StatusFound)
						return
					}
					_ = src.Close()
				}
			}
		}
		if err := writer.Close(); err != nil {
			http.Redirect(w, r, "/employee/paperwork/"+encodePathTail(pathTail)+"?error=Unable+to+finalize+submission", http.StatusFound)
			return
		}
		apiReq, err = http.NewRequestWithContext(r.Context(), http.MethodPost, apiURL, &body)
		if err != nil {
			http.Redirect(w, r, "/employee/paperwork/"+encodePathTail(pathTail)+"?error=Unable+to+submit+paperwork", http.StatusFound)
			return
		}
		apiReq.Header.Set("Content-Type", writer.FormDataContentType())
	} else {
		if err := r.ParseForm(); err != nil {
			http.Redirect(w, r, "/employee/paperwork/"+encodePathTail(pathTail)+"?error=Invalid+form+submission", http.StatusFound)
			return
		}
		values := url.Values{}
		for key, items := range r.PostForm {
			for _, item := range items {
				values.Add(key, strings.TrimSpace(item))
			}
		}
		apiReq, err = http.NewRequestWithContext(r.Context(), http.MethodPost, apiURL, strings.NewReader(values.Encode()))
		if err != nil {
			http.Redirect(w, r, "/employee/paperwork/"+encodePathTail(pathTail)+"?error=Unable+to+submit+paperwork", http.StatusFound)
			return
		}
		apiReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		http.Redirect(w, r, "/employee/paperwork/"+encodePathTail(pathTail)+"?error=Service+unavailable", http.StatusFound)
		return
	}
	defer apiResp.Body.Close()
	respBody, _ := io.ReadAll(apiResp.Body)
	if apiResp.StatusCode != http.StatusOK {
		msg := "unable to submit paperwork"
		var errPayload map[string]string
		if err := json.Unmarshal(respBody, &errPayload); err == nil && strings.TrimSpace(errPayload["error"]) != "" {
			msg = errPayload["error"]
		}
		http.Redirect(w, r, "/employee/paperwork/"+encodePathTail(pathTail)+"?error="+url.QueryEscape(msg), http.StatusFound)
		return
	}
	target := strings.ToLower(strings.TrimSpace(r.PostForm.Get("paperwork_target")))
	submittedFormLabel := "paperwork"
	if target == "i9" {
		submittedFormLabel = "I-9"
	} else if target == "w4" {
		submittedFormLabel = "W-4"
	}
	var payload publicPaperworkSubmitResponse
	if err := json.Unmarshal(respBody, &payload); err != nil {
		payload = publicPaperworkSubmitResponse{}
	}
	if payload.AllSubmitted {
		if s.sessionIsValid(r) && strings.TrimSpace(payload.LocationNumber) != "" && strings.TrimSpace(payload.TimePunchName) != "" {
			http.Redirect(
				w,
				r,
				"/admin/locations/"+url.PathEscape(payload.LocationNumber)+"/employees/"+url.PathEscape(payload.TimePunchName)+"?message="+url.QueryEscape("Paperwork submitted")+"#paperwork-view",
				http.StatusFound,
			)
			return
		}
		http.Redirect(w, r, "/employee/paperwork/"+encodePathTail(pathTail)+"?submitted=1", http.StatusFound)
		return
	}
	http.Redirect(w, r, "/employee/paperwork/"+encodePathTail(pathTail)+"?message="+url.QueryEscape(submittedFormLabel+" submitted. Please complete the remaining form."), http.StatusFound)
}

func (s *server) renderPublicPaperworkClosedPage(w http.ResponseWriter, r *http.Request) {
	submitted := shouldRenderPaperworkSubmittedFromQuery(r)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if submitted {
		_, _ = io.WriteString(w, `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Paperwork Submitted</title><style>body{margin:0;padding:16px;background:#f4f1ec;font-family:Manrope,Segoe UI,sans-serif;color:#1f232a}.card{max-width:640px;margin:40px auto;background:#fff;border:1px solid #e2d5c4;border-radius:14px;padding:18px;box-shadow:0 10px 24px rgba(33,28,23,.08)}h1{margin:0 0 8px;font-size:1.3rem}p{margin:0 0 10px;color:#68707b;line-height:1.4}</style></head><body><section class="card"><h1>Paperwork Submitted</h1><p>Thank you. Your paperwork was submitted successfully.</p><p>This link is now closed.</p></section></body></html>`)
		return
	}
	_, _ = io.WriteString(w, `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Link Closed</title><style>body{margin:0;padding:16px;background:#f4f1ec;font-family:Manrope,Segoe UI,sans-serif;color:#1f232a}.card{max-width:640px;margin:40px auto;background:#fff;border:1px solid #e2d5c4;border-radius:14px;padding:18px;box-shadow:0 10px 24px rgba(33,28,23,.08)}h1{margin:0 0 8px;font-size:1.3rem}p{margin:0 0 10px;color:#68707b;line-height:1.4}</style></head><body><section class="card"><h1>Link Closed</h1><p>This paperwork link has already been used and is no longer active.</p><p>Please contact your admin if updates are needed.</p></section></body></html>`)
}

func shouldRenderPaperworkSubmittedFromQuery(r *http.Request) bool {
	if strings.TrimSpace(r.URL.Query().Get("submitted")) == "1" {
		return true
	}
	msg := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("message")))
	return strings.Contains(msg, "paperwork submitted")
}

func (s *server) publicTimePunchPage(w http.ResponseWriter, r *http.Request, token string) {
	payload, err := s.fetchPublicTimePunchData(r, token)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	resolvedTimePunchName, resolvedEmployeeName := s.resolvePublicFormTeamMember(r, payload.LocationNumber, payload.Employees)
	if err := renderHTMLTemplate(w, s.publicTimePunchTmpl, pageData{
		Token:                 token,
		Location:              &locationView{Number: payload.LocationNumber, Name: payload.LocationName},
		Employees:             payload.Employees,
		ResolvedTimePunchName: resolvedTimePunchName,
		ResolvedEmployeeName:  resolvedEmployeeName,
		SuccessMessage:        r.URL.Query().Get("message"),
		Error:                 r.URL.Query().Get("error"),
	}); err != nil {
		http.Error(w, "template render failed", http.StatusInternalServerError)
		log.Printf("public time punch template render failed: %v", err)
	}
}

func (s *server) publicTimePunchSubmit(w http.ResponseWriter, r *http.Request, token string) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/time-punch/"+url.PathEscape(token)+"?error=Invalid+form+submission", http.StatusFound)
		return
	}
	timePunchName := strings.TrimSpace(r.FormValue("time_punch_name"))
	if payload, err := s.fetchPublicTimePunchData(r, token); err == nil {
		if resolved, _ := s.resolvePublicFormTeamMember(r, payload.LocationNumber, payload.Employees); strings.TrimSpace(resolved) != "" {
			timePunchName = resolved
		}
	}
	payload := map[string]any{
		"timePunchName":            timePunchName,
		"punchDate":                strings.TrimSpace(r.FormValue("punch_date")),
		"timeIn":                   strings.TrimSpace(r.FormValue("time_in")),
		"timeOut":                  strings.TrimSpace(r.FormValue("time_out")),
		"note":                     strings.TrimSpace(r.FormValue("note")),
		"forgotBreakClockInReturn": strings.TrimSpace(r.FormValue("forgot_break_clock_in_return")) != "",
	}
	body, _ := json.Marshal(payload)
	apiURL := s.apiBaseURL + "/api/public/time-punch/" + url.PathEscape(token)
	apiReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, apiURL, bytes.NewReader(body))
	if err != nil {
		http.Redirect(w, r, "/time-punch/"+url.PathEscape(token)+"?error=Unable+to+submit", http.StatusFound)
		return
	}
	apiReq.Header.Set("Content-Type", "application/json")
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		http.Redirect(w, r, "/time-punch/"+url.PathEscape(token)+"?error=Service+unavailable", http.StatusFound)
		return
	}
	defer apiResp.Body.Close()
	respBody, _ := io.ReadAll(apiResp.Body)
	if apiResp.StatusCode != http.StatusOK {
		msg := "unable to submit time punch"
		var errPayload map[string]string
		if err := json.Unmarshal(respBody, &errPayload); err == nil && strings.TrimSpace(errPayload["error"]) != "" {
			msg = errPayload["error"]
		}
		http.Redirect(w, r, "/time-punch/"+url.PathEscape(token)+"?error="+url.QueryEscape(msg), http.StatusFound)
		return
	}
	http.Redirect(w, r, "/time-punch/"+url.PathEscape(token)+"?message="+url.QueryEscape("Time punch correction submitted"), http.StatusFound)
}

func (s *server) publicTimeOffPage(w http.ResponseWriter, r *http.Request, token string) {
	payload, err := s.fetchPublicTimeOffData(r, token)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	resolvedTimePunchName, resolvedEmployeeName := s.resolvePublicFormTeamMember(r, payload.LocationNumber, payload.Employees)
	if err := renderHTMLTemplate(w, s.publicTimeOffTmpl, pageData{
		Token:                 token,
		Location:              &locationView{Number: payload.LocationNumber, Name: payload.LocationName},
		Employees:             payload.Employees,
		ResolvedTimePunchName: resolvedTimePunchName,
		ResolvedEmployeeName:  resolvedEmployeeName,
		SuccessMessage:        r.URL.Query().Get("message"),
		Error:                 r.URL.Query().Get("error"),
	}); err != nil {
		http.Error(w, "template render failed", http.StatusInternalServerError)
		log.Printf("public time off template render failed: %v", err)
	}
}

func (s *server) publicTimeOffSubmit(w http.ResponseWriter, r *http.Request, token string) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/time-off/"+url.PathEscape(token)+"?error=Invalid+form+submission", http.StatusFound)
		return
	}
	startDate := strings.TrimSpace(r.FormValue("start_date"))
	endDate := strings.TrimSpace(r.FormValue("end_date"))
	if endDate == "" {
		endDate = startDate
	}
	timePunchName := strings.TrimSpace(r.FormValue("time_punch_name"))
	if payload, err := s.fetchPublicTimeOffData(r, token); err == nil {
		if resolved, _ := s.resolvePublicFormTeamMember(r, payload.LocationNumber, payload.Employees); strings.TrimSpace(resolved) != "" {
			timePunchName = resolved
		}
	}
	payload := map[string]string{
		"timePunchName": timePunchName,
		"startDate":     startDate,
		"endDate":       endDate,
	}
	body, _ := json.Marshal(payload)
	apiURL := s.apiBaseURL + "/api/public/time-off/" + url.PathEscape(token)
	apiReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, apiURL, bytes.NewReader(body))
	if err != nil {
		http.Redirect(w, r, "/time-off/"+url.PathEscape(token)+"?error=Unable+to+submit", http.StatusFound)
		return
	}
	apiReq.Header.Set("Content-Type", "application/json")
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		http.Redirect(w, r, "/time-off/"+url.PathEscape(token)+"?error=Service+unavailable", http.StatusFound)
		return
	}
	defer apiResp.Body.Close()
	respBody, _ := io.ReadAll(apiResp.Body)
	if apiResp.StatusCode != http.StatusOK {
		msg := "unable to submit vacation request"
		var errPayload map[string]string
		if err := json.Unmarshal(respBody, &errPayload); err == nil && strings.TrimSpace(errPayload["error"]) != "" {
			msg = errPayload["error"]
		}
		http.Redirect(w, r, "/time-off/"+url.PathEscape(token)+"?error="+url.QueryEscape(msg), http.StatusFound)
		return
	}
	http.Redirect(w, r, "/time-off/"+url.PathEscape(token)+"?message="+url.QueryEscape("Vacation request submitted"), http.StatusFound)
}

func (s *server) publicUniformOrderPage(w http.ResponseWriter, r *http.Request, token string) {
	payload, err := s.fetchPublicUniformOrderData(r, token)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if err := renderHTMLTemplate(w, s.publicUniformTmpl, pageData{
		Token:          token,
		Location:       &locationView{Number: payload.LocationNumber, Name: payload.LocationName},
		UniformItems:   payload.Items,
		SuccessMessage: r.URL.Query().Get("message"),
		Error:          r.URL.Query().Get("error"),
	}); err != nil {
		http.Error(w, "template render failed", http.StatusInternalServerError)
		log.Printf("public uniform order template render failed: %v", err)
	}
}

func (s *server) publicUniformOrderItemPage(w http.ResponseWriter, r *http.Request, token string, itemID int64) {
	payload, err := s.fetchPublicUniformOrderData(r, token)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	var selected *uniformItemView
	for i := range payload.Items {
		if payload.Items[i].ID == itemID {
			selected = &payload.Items[i]
			break
		}
	}
	if selected == nil {
		http.NotFound(w, r)
		return
	}
	resolvedTimePunchName, resolvedEmployeeName := s.resolvePublicFormTeamMember(r, payload.LocationNumber, payload.Employees)
	if err := renderHTMLTemplate(w, s.publicUniformItemTmpl, pageData{
		Token:                 token,
		Location:              &locationView{Number: payload.LocationNumber, Name: payload.LocationName},
		Employees:             payload.Employees,
		UniformItem:           selected,
		ResolvedTimePunchName: resolvedTimePunchName,
		ResolvedEmployeeName:  resolvedEmployeeName,
		SuccessMessage:        r.URL.Query().Get("message"),
		Error:                 r.URL.Query().Get("error"),
	}); err != nil {
		http.Error(w, "template render failed", http.StatusInternalServerError)
		log.Printf("public uniform order item template render failed: %v", err)
	}
}

func (s *server) publicUniformOrderItemSubmit(w http.ResponseWriter, r *http.Request, token string, itemID int64) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/uniform-order/"+url.PathEscape(token)+"/item/"+strconv.FormatInt(itemID, 10)+"?error=Invalid+form+submission", http.StatusFound)
		return
	}
	quantity, err := strconv.ParseInt(strings.TrimSpace(r.FormValue("quantity")), 10, 64)
	if err != nil || quantity <= 0 {
		http.Redirect(w, r, "/uniform-order/"+url.PathEscape(token)+"/item/"+strconv.FormatInt(itemID, 10)+"?error=Quantity+must+be+at+least+1", http.StatusFound)
		return
	}
	timePunchName := strings.TrimSpace(r.FormValue("time_punch_name"))
	var selectedItem *uniformItemView
	if orderPayload, err := s.fetchPublicUniformOrderData(r, token); err == nil {
		if resolved, _ := s.resolvePublicFormTeamMember(r, orderPayload.LocationNumber, orderPayload.Employees); strings.TrimSpace(resolved) != "" {
			timePunchName = resolved
		}
		for i := range orderPayload.Items {
			if orderPayload.Items[i].ID == itemID {
				selectedItem = &orderPayload.Items[i]
				break
			}
		}
	}
	lineItem := map[string]any{
		"itemId":         itemID,
		"size":           strings.TrimSpace(r.FormValue("size")),
		"sizeSelections": parseFormSizeSelectionsForItem(r.PostForm["size_field_label"], r.PostForm["size_field_value"], selectedItem),
		"sizeValues":     parseFormSizeValues(r.PostForm["size_field_value"]),
		"note":           strings.TrimSpace(r.FormValue("note")),
		"quantity":       quantity,
	}
	if selectedItem != nil && strings.EqualFold(strings.TrimSpace(selectedItem.SystemKey), uniformSystemKeyShoes) {
		shoeItemNumber := strings.TrimSpace(r.FormValue("shoe_item_number"))
		if shoeItemNumber == "" {
			http.Redirect(w, r, "/uniform-order/"+url.PathEscape(token)+"/item/"+strconv.FormatInt(itemID, 10)+"?error=Shoe+item+number+is+required", http.StatusFound)
			return
		}
		lineItem = map[string]any{
			"itemId":         int64(0),
			"orderType":      uniformSystemKeyShoes,
			"shoeItemNumber": shoeItemNumber,
			"shoePrice":      fmt.Sprintf("%.2f", selectedItem.Price),
			"note":           strings.TrimSpace(r.FormValue("note")),
			"quantity":       quantity,
		}
	}
	payload := map[string]any{
		"timePunchName": timePunchName,
		"items":         []map[string]any{lineItem},
	}
	body, _ := json.Marshal(payload)
	apiURL := s.apiBaseURL + "/api/public/uniform-order/" + url.PathEscape(token)
	apiReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, apiURL, bytes.NewReader(body))
	if err != nil {
		http.Redirect(w, r, "/uniform-order/"+url.PathEscape(token)+"/item/"+strconv.FormatInt(itemID, 10)+"?error=Unable+to+submit+order", http.StatusFound)
		return
	}
	apiReq.Header.Set("Content-Type", "application/json")
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		http.Redirect(w, r, "/uniform-order/"+url.PathEscape(token)+"/item/"+strconv.FormatInt(itemID, 10)+"?error=Service+unavailable", http.StatusFound)
		return
	}
	defer apiResp.Body.Close()
	respBody, _ := io.ReadAll(apiResp.Body)
	if apiResp.StatusCode != http.StatusOK {
		msg := "unable to submit uniform order"
		var errPayload map[string]string
		if err := json.Unmarshal(respBody, &errPayload); err == nil && strings.TrimSpace(errPayload["error"]) != "" {
			msg = errPayload["error"]
		}
		http.Redirect(w, r, "/uniform-order/"+url.PathEscape(token)+"/item/"+strconv.FormatInt(itemID, 10)+"?error="+url.QueryEscape(msg), http.StatusFound)
		return
	}
	http.Redirect(w, r, "/uniform-order/"+url.PathEscape(token)+"?message="+url.QueryEscape("Uniform order submitted"), http.StatusFound)
}

func (s *server) fetchPublicUniformOrderData(r *http.Request, token string) (publicUniformOrderResponse, error) {
	apiURL := s.apiBaseURL + "/api/public/uniform-order/" + url.PathEscape(token)
	apiReq, err := http.NewRequestWithContext(r.Context(), http.MethodGet, apiURL, nil)
	if err != nil {
		return publicUniformOrderResponse{}, err
	}
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		return publicUniformOrderResponse{}, err
	}
	defer apiResp.Body.Close()
	if apiResp.StatusCode != http.StatusOK {
		return publicUniformOrderResponse{}, errors.New("invalid token")
	}
	var payload publicUniformOrderResponse
	if err := json.NewDecoder(apiResp.Body).Decode(&payload); err != nil {
		return publicUniformOrderResponse{}, err
	}
	return payload, nil
}

func (s *server) fetchPublicTimePunchData(r *http.Request, token string) (publicTimePunchResponse, error) {
	apiURL := s.apiBaseURL + "/api/public/time-punch/" + url.PathEscape(token)
	apiReq, err := http.NewRequestWithContext(r.Context(), http.MethodGet, apiURL, nil)
	if err != nil {
		return publicTimePunchResponse{}, err
	}
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		return publicTimePunchResponse{}, err
	}
	defer apiResp.Body.Close()
	if apiResp.StatusCode != http.StatusOK {
		return publicTimePunchResponse{}, errors.New("invalid token")
	}
	var payload publicTimePunchResponse
	if err := json.NewDecoder(apiResp.Body).Decode(&payload); err != nil {
		return publicTimePunchResponse{}, err
	}
	return payload, nil
}

func (s *server) fetchPublicTimeOffData(r *http.Request, token string) (publicTimeOffResponse, error) {
	apiURL := s.apiBaseURL + "/api/public/time-off/" + url.PathEscape(token)
	apiReq, err := http.NewRequestWithContext(r.Context(), http.MethodGet, apiURL, nil)
	if err != nil {
		return publicTimeOffResponse{}, err
	}
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		return publicTimeOffResponse{}, err
	}
	defer apiResp.Body.Close()
	if apiResp.StatusCode != http.StatusOK {
		return publicTimeOffResponse{}, errors.New("invalid token")
	}
	var payload publicTimeOffResponse
	if err := json.NewDecoder(apiResp.Body).Decode(&payload); err != nil {
		return publicTimeOffResponse{}, err
	}
	return payload, nil
}

func (s *server) resolvePublicFormTeamMember(r *http.Request, locationNumber string, employees []employeeView) (string, string) {
	currentUser, err := s.fetchSessionUserByRoles(r, []string{"team"})
	if err != nil || currentUser == nil {
		return "", ""
	}
	if !strings.EqualFold(strings.TrimSpace(currentUser.LocationNumber), strings.TrimSpace(locationNumber)) {
		return "", ""
	}
	currentTPN := strings.TrimSpace(currentUser.TimePunchName)
	if currentTPN == "" {
		return "", ""
	}
	for _, employee := range employees {
		employeeTPN := strings.TrimSpace(employee.TimePunchName)
		if !strings.EqualFold(employeeTPN, currentTPN) {
			continue
		}
		displayName := strings.TrimSpace(employee.FirstName + " " + employee.LastName)
		if displayName == "" {
			displayName = employeeTPN
		}
		return employeeTPN, displayName
	}
	return "", ""
}

func (s *server) publicPhotoUploadSubmit(w http.ResponseWriter, r *http.Request, token string) {
	if err := r.ParseMultipartForm(20 << 20); err != nil {
		http.Redirect(w, r, "/employee/photo-upload/"+url.PathEscape(token)+"?error=Invalid+upload", http.StatusFound)
		return
	}
	file, header, err := r.FormFile("photo_file")
	if err != nil {
		http.Redirect(w, r, "/employee/photo-upload/"+url.PathEscape(token)+"?error=Photo+file+is+required", http.StatusFound)
		return
	}
	defer file.Close()

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("photo_file", header.Filename)
	if err != nil {
		http.Redirect(w, r, "/employee/photo-upload/"+url.PathEscape(token)+"?error=Unable+to+prepare+upload", http.StatusFound)
		return
	}
	if _, err := io.Copy(part, file); err != nil {
		http.Redirect(w, r, "/employee/photo-upload/"+url.PathEscape(token)+"?error=Unable+to+read+upload", http.StatusFound)
		return
	}
	for _, key := range []string{"crop_x", "crop_y", "crop_size"} {
		if value := strings.TrimSpace(r.FormValue(key)); value != "" {
			_ = writer.WriteField(key, value)
		}
	}
	_ = writer.Close()

	apiURL := s.apiBaseURL + "/api/public/employee-photo-upload/" + url.PathEscape(token)
	apiReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, apiURL, &body)
	if err != nil {
		http.Redirect(w, r, "/employee/photo-upload/"+url.PathEscape(token)+"?error=Unable+to+send+upload", http.StatusFound)
		return
	}
	apiReq.Header.Set("Content-Type", writer.FormDataContentType())
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		http.Redirect(w, r, "/employee/photo-upload/"+url.PathEscape(token)+"?error=Upload+service+unavailable", http.StatusFound)
		return
	}
	defer apiResp.Body.Close()
	respBody, _ := io.ReadAll(apiResp.Body)
	if apiResp.StatusCode != http.StatusOK {
		msg := "unable to upload photo"
		var payload map[string]string
		if err := json.Unmarshal(respBody, &payload); err == nil && payload["error"] != "" {
			msg = payload["error"]
		}
		http.Redirect(w, r, "/employee/photo-upload/"+url.PathEscape(token)+"?error="+url.QueryEscape(msg), http.StatusFound)
		return
	}
	http.Redirect(w, r, "/employee/photo-upload/"+url.PathEscape(token)+"?submitted=1", http.StatusFound)
}

func (s *server) renderPublicPhotoUploadClosedPage(w http.ResponseWriter, r *http.Request) {
	submitted := shouldRenderPhotoUploadSubmittedFromQuery(r)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if submitted {
		_, _ = io.WriteString(w, `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Photo Uploaded</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Manrope:wght@500;600;700;800&family=Space+Grotesk:wght@500;700&display=swap" rel="stylesheet">
<script>
(function () {
  var stored = localStorage.getItem("cfasuite-theme");
  var prefersDark = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
  var theme = stored === "light" || stored === "dark" ? stored : (prefersDark ? "dark" : "light");
  document.documentElement.classList.toggle("dark", theme === "dark");
})();
</script>
<style>
:root{--bg:#fff;--fg:#09090b;--card:#fff;--muted:#71717a;--border:#e4e4e7}
html.dark{--bg:#09090b;--fg:#fafafa;--card:#09090b;--muted:#a1a1aa;--border:#3f3f46}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font-family:"Manrope",sans-serif}
.wrap{max-width:760px;margin:0 auto;padding:4rem 1rem}
.card{border:1px solid var(--border);border-radius:12px;background:var(--card);padding:1rem}
h1{margin:0 0 .6rem;font-size:1.35rem;font-family:"Space Grotesk",sans-serif}
p{margin:0 0 .5rem;color:var(--muted);line-height:1.45}
</style>
</head>
<body>
  <div class="wrap">
    <section class="card">
      <h1>Photo Uploaded</h1>
      <p>Thank you. Your profile photo was uploaded successfully.</p>
      <p>This link is now closed.</p>
    </section>
  </div>
</body>
</html>`)
		return
	}
	_, _ = io.WriteString(w, `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Link Closed</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Manrope:wght@500;600;700;800&family=Space+Grotesk:wght@500;700&display=swap" rel="stylesheet">
<script>
(function () {
  var stored = localStorage.getItem("cfasuite-theme");
  var prefersDark = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
  var theme = stored === "light" || stored === "dark" ? stored : (prefersDark ? "dark" : "light");
  document.documentElement.classList.toggle("dark", theme === "dark");
})();
</script>
<style>
:root{--bg:#fff;--fg:#09090b;--card:#fff;--muted:#71717a;--border:#e4e4e7}
html.dark{--bg:#09090b;--fg:#fafafa;--card:#09090b;--muted:#a1a1aa;--border:#3f3f46}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font-family:"Manrope",sans-serif}
.wrap{max-width:760px;margin:0 auto;padding:4rem 1rem}
.card{border:1px solid var(--border);border-radius:12px;background:var(--card);padding:1rem}
h1{margin:0 0 .6rem;font-size:1.35rem;font-family:"Space Grotesk",sans-serif}
p{margin:0 0 .5rem;color:var(--muted);line-height:1.45}
</style>
</head>
<body>
  <div class="wrap">
    <section class="card">
      <h1>Link Closed</h1>
      <p>This photo upload link has already been used or expired.</p>
      <p>Please contact your admin for a new link.</p>
    </section>
  </div>
</body>
</html>`)
}

func shouldRenderPhotoUploadSubmittedFromQuery(r *http.Request) bool {
	if strings.TrimSpace(r.URL.Query().Get("submitted")) == "1" {
		return true
	}
	msg := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("message")))
	return strings.Contains(msg, "photo uploaded")
}

func (s *server) requireMasterAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		currentUser, err := s.fetchSessionUserByRoles(r, []string{"admin"})
		if err != nil || currentUser == nil {
			if locationUser, locationErr := s.fetchSessionUserByRoles(r, []string{"restaurant"}); locationErr == nil && locationUser != nil {
				locationNumber := strings.TrimSpace(locationUser.LocationNumber)
				if locationNumber != "" {
					http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber), http.StatusFound)
					return
				}
			}
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *server) requireLocationPortal(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		currentUser, err := s.fetchSessionUserByRoles(r, []string{"admin", "restaurant"})
		if err != nil || currentUser == nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		if strings.EqualFold(strings.TrimSpace(currentUser.Role), "restaurant") {
			locationNumber := strings.TrimSpace(currentUser.LocationNumber)
			if locationNumber == "" {
				http.Redirect(w, r, "/login?error=Location+session+is+not+assigned", http.StatusFound)
				return
			}
			requestedLocation, ok := locationNumberFromAdminLocationPath(r.URL.Path)
			if !ok || !strings.EqualFold(strings.TrimSpace(requestedLocation), locationNumber) {
				http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"?error="+url.QueryEscape("location access denied"), http.StatusFound)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *server) requireTeam(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		currentUser, err := s.fetchSessionUserByRoles(r, []string{"team"})
		if err != nil || currentUser == nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *server) sessionIsValid(r *http.Request) bool {
	_, err := s.fetchSessionUser(r)
	return err == nil
}

func (s *server) fetchSessionUser(r *http.Request) (*authSessionView, error) {
	return s.fetchSessionUserByRoles(r, []string{"admin", "restaurant", "team"})
}

func (s *server) fetchSessionUserByRoles(r *http.Request, roles []string) (*authSessionView, error) {
	for _, role := range roles {
		sessionValue := sessionValueForRole(r, role)
		if sessionValue == "" {
			continue
		}
		user, err := s.fetchSessionUserWithSessionValue(r, sessionValue)
		if err == nil {
			return user, nil
		}
	}
	return nil, errors.New("unauthorized")
}

func (s *server) fetchSessionUserWithSessionValue(r *http.Request, sessionValue string) (*authSessionView, error) {
	apiReq, err := http.NewRequestWithContext(r.Context(), http.MethodGet, s.apiBaseURL+"/api/auth/me", nil)
	if err != nil {
		return nil, err
	}
	copySessionCookieHeaderForValue(apiReq, sessionValue)

	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		return nil, err
	}
	defer apiResp.Body.Close()
	if apiResp.StatusCode != http.StatusOK {
		return nil, errors.New("unauthorized")
	}
	var payload authSessionView
	if err := json.NewDecoder(apiResp.Body).Decode(&payload); err != nil {
		return nil, err
	}
	payload.Role = strings.ToLower(strings.TrimSpace(payload.Role))
	return &payload, nil
}

func redirectPathForUser(user *authSessionView) string {
	if user == nil {
		return "/login"
	}
	switch strings.ToLower(strings.TrimSpace(user.Role)) {
	case "team":
		return "/team"
	case "restaurant":
		locationNumber := strings.TrimSpace(user.LocationNumber)
		if locationNumber != "" {
			return "/admin/locations/" + url.PathEscape(locationNumber)
		}
		return "/login"
	}
	return "/admin"
}

func locationNumberFromAdminLocationPath(path string) (string, bool) {
	trimmed := strings.TrimPrefix(path, "/admin/locations/")
	trimmed = strings.Trim(trimmed, "/")
	if trimmed == "" {
		return "", false
	}
	parts := strings.Split(trimmed, "/")
	if len(parts) == 0 || strings.TrimSpace(parts[0]) == "" {
		return "", false
	}
	locationNumber, err := url.PathUnescape(parts[0])
	if err != nil || strings.TrimSpace(locationNumber) == "" {
		return "", false
	}
	return locationNumber, true
}

func (s *server) fetchCSRFToken(r *http.Request) (string, error) {
	sessionValue := chooseAPISessionValue(r)
	return s.fetchCSRFTokenWithSessionValue(r, sessionValue)
}

func (s *server) fetchCSRFTokenForRole(r *http.Request, role string) (string, error) {
	return s.fetchCSRFTokenWithSessionValue(r, sessionValueForRole(r, role))
}

func (s *server) fetchCSRFTokenWithSessionValue(r *http.Request, sessionValue string) (string, error) {
	if strings.TrimSpace(sessionValue) == "" {
		return "", errors.New("unauthorized")
	}
	apiReq, err := http.NewRequestWithContext(r.Context(), http.MethodGet, s.apiBaseURL+"/api/auth/csrf", nil)
	if err != nil {
		return "", err
	}
	copySessionCookieHeaderForValue(apiReq, sessionValue)

	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		return "", err
	}
	defer apiResp.Body.Close()

	if apiResp.StatusCode != http.StatusOK {
		return "", errors.New("unauthorized")
	}

	var payload authTokenResponse
	if err := json.NewDecoder(apiResp.Body).Decode(&payload); err != nil {
		return "", err
	}
	if payload.CSRFToken == "" {
		return "", errors.New("missing csrf token")
	}
	return payload.CSRFToken, nil
}

func sessionValueForRole(r *http.Request, role string) string {
	cookieName := cookieNameForSessionRole(role)
	if cookieName == "" {
		return ""
	}
	cookie, err := r.Cookie(cookieName)
	if err != nil || strings.TrimSpace(cookie.Value) == "" {
		return ""
	}
	return strings.TrimSpace(cookie.Value)
}

func (s *server) fetchLocationsPage(r *http.Request, page, perPage int) (*locationsListResponse, error) {
	apiReq, err := http.NewRequestWithContext(
		r.Context(),
		http.MethodGet,
		s.apiBaseURL+"/api/admin/locations?page="+strconv.Itoa(page)+"&per_page="+strconv.Itoa(perPage),
		nil,
	)
	if err != nil {
		return nil, err
	}
	copySessionCookieHeader(r, apiReq)
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		return nil, err
	}
	defer apiResp.Body.Close()
	if apiResp.StatusCode != http.StatusOK {
		return nil, errors.New("failed to fetch locations")
	}
	var payload locationsListResponse
	if err := json.NewDecoder(apiResp.Body).Decode(&payload); err != nil {
		return nil, err
	}
	for i := range payload.Locations {
		normalizeLocationView(&payload.Locations[i])
	}
	return &payload, nil
}

func (s *server) fetchLocation(r *http.Request, number string) (*locationView, error) {
	apiReq, err := http.NewRequestWithContext(
		r.Context(),
		http.MethodGet,
		s.apiBaseURL+"/api/admin/locations/"+url.PathEscape(number),
		nil,
	)
	if err != nil {
		return nil, err
	}
	copySessionCookieHeader(r, apiReq)
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		return nil, err
	}
	defer apiResp.Body.Close()
	if apiResp.StatusCode != http.StatusOK {
		return nil, errors.New("location not found")
	}
	var payload locationDetailResponse
	if err := json.NewDecoder(apiResp.Body).Decode(&payload); err != nil {
		return nil, err
	}
	normalizeLocationView(&payload.Location)
	return &payload.Location, nil
}

func (s *server) fetchLocationSettings(r *http.Request, number string) (*locationSettingsView, error) {
	apiReq, err := http.NewRequestWithContext(
		r.Context(),
		http.MethodGet,
		s.apiBaseURL+"/api/admin/locations/"+url.PathEscape(number)+"/settings",
		nil,
	)
	if err != nil {
		return nil, err
	}
	copySessionCookieHeader(r, apiReq)
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		return nil, err
	}
	defer apiResp.Body.Close()
	if apiResp.StatusCode != http.StatusOK {
		return nil, errors.New("failed to fetch location settings")
	}
	var payload locationSettingsResponse
	if err := json.NewDecoder(apiResp.Body).Decode(&payload); err != nil {
		return nil, err
	}
	if strings.TrimSpace(payload.Settings.BusinessName) == "" {
		payload.Settings.BusinessName = strings.TrimSpace(payload.Settings.W4EmployerName)
	}
	if strings.TrimSpace(payload.Settings.BusinessStreet) == "" {
		payload.Settings.BusinessStreet = strings.TrimSpace(payload.Settings.W4EmployerStreet)
	}
	if strings.TrimSpace(payload.Settings.BusinessCity) == "" {
		payload.Settings.BusinessCity = strings.TrimSpace(payload.Settings.W4EmployerCity)
	}
	if strings.TrimSpace(payload.Settings.BusinessState) == "" {
		payload.Settings.BusinessState = strings.TrimSpace(payload.Settings.W4EmployerState)
	}
	if strings.TrimSpace(payload.Settings.BusinessEIN) == "" {
		payload.Settings.BusinessEIN = strings.TrimSpace(payload.Settings.W4EmployerEIN)
	}
	if strings.TrimSpace(payload.Settings.BusinessAddress) == "" {
		addressParts := make([]string, 0, 3)
		if strings.TrimSpace(payload.Settings.BusinessStreet) != "" {
			addressParts = append(addressParts, strings.TrimSpace(payload.Settings.BusinessStreet))
		}
		if strings.TrimSpace(payload.Settings.BusinessCity) != "" {
			addressParts = append(addressParts, strings.TrimSpace(payload.Settings.BusinessCity))
		}
		if strings.TrimSpace(payload.Settings.BusinessState) != "" {
			addressParts = append(addressParts, strings.TrimSpace(payload.Settings.BusinessState))
		}
		payload.Settings.BusinessAddress = strings.Join(addressParts, ", ")
	}
	if strings.TrimSpace(payload.Settings.BusinessAddress) == "" {
		payload.Settings.BusinessAddress = strings.TrimSpace(payload.Settings.W4EmployerAddress)
	}
	payload.Settings.Departments = normalizeDepartments(payload.Settings.Departments)
	return &payload.Settings, nil
}

func (s *server) fetchLocationEmployees(r *http.Request, number string) ([]employeeView, error) {
	apiReq, err := http.NewRequestWithContext(
		r.Context(),
		http.MethodGet,
		s.apiBaseURL+"/api/admin/locations/"+url.PathEscape(number)+"/employees",
		nil,
	)
	if err != nil {
		return nil, err
	}
	copySessionCookieHeader(r, apiReq)
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		return nil, err
	}
	defer apiResp.Body.Close()
	if apiResp.StatusCode != http.StatusOK {
		return nil, errors.New("failed to fetch employees")
	}

	var payload locationEmployeesResponse
	if err := json.NewDecoder(apiResp.Body).Decode(&payload); err != nil {
		return nil, err
	}
	for i := range payload.Employees {
		normalizeEmployeeView(&payload.Employees[i])
	}
	return payload.Employees, nil
}

func (s *server) fetchLocationDepartments(r *http.Request, number string) ([]departmentView, error) {
	apiReq, err := http.NewRequestWithContext(
		r.Context(),
		http.MethodGet,
		s.apiBaseURL+"/api/admin/locations/"+url.PathEscape(number)+"/departments",
		nil,
	)
	if err != nil {
		return nil, err
	}
	copySessionCookieHeader(r, apiReq)
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		return nil, err
	}
	defer apiResp.Body.Close()
	if apiResp.StatusCode != http.StatusOK {
		return nil, errors.New("failed to fetch departments")
	}
	var payload locationDepartmentsResponse
	if err := json.NewDecoder(apiResp.Body).Decode(&payload); err != nil {
		return nil, err
	}
	for i := range payload.Departments {
		payload.Departments[i].CreatedAt = formatDateTimeDisplay(payload.Departments[i].CreatedAt)
	}
	return payload.Departments, nil
}

func (s *server) fetchLocationJobs(r *http.Request, number string) ([]jobView, error) {
	apiReq, err := http.NewRequestWithContext(
		r.Context(),
		http.MethodGet,
		s.apiBaseURL+"/api/admin/locations/"+url.PathEscape(number)+"/jobs",
		nil,
	)
	if err != nil {
		return nil, err
	}
	copySessionCookieHeader(r, apiReq)
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		return nil, err
	}
	defer apiResp.Body.Close()
	if apiResp.StatusCode != http.StatusOK {
		return nil, errors.New("failed to fetch jobs")
	}
	var payload locationJobsResponse
	if err := json.NewDecoder(apiResp.Body).Decode(&payload); err != nil {
		return nil, err
	}
	for i := range payload.Jobs {
		payload.Jobs[i].CreatedAt = formatDateTimeDisplay(payload.Jobs[i].CreatedAt)
		payload.Jobs[i].PayAmountDisplay = formatPayAmountInput(payload.Jobs[i].PayAmountCents)
	}
	return payload.Jobs, nil
}

func (s *server) fetchEmployeeAdditionalCompensations(r *http.Request, number, timePunchName string) ([]employeeAdditionalCompView, error) {
	apiReq, err := http.NewRequestWithContext(
		r.Context(),
		http.MethodGet,
		s.apiBaseURL+"/api/admin/locations/"+url.PathEscape(number)+"/employees/"+url.PathEscape(timePunchName)+"/additional-compensations",
		nil,
	)
	if err != nil {
		return nil, err
	}
	copySessionCookieHeader(r, apiReq)
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		return nil, err
	}
	defer apiResp.Body.Close()
	if apiResp.StatusCode != http.StatusOK {
		return nil, errors.New("failed to fetch additional compensations")
	}
	var payload employeeAdditionalCompensationsResponse
	if err := json.NewDecoder(apiResp.Body).Decode(&payload); err != nil {
		return nil, err
	}
	for i := range payload.Compensations {
		payload.Compensations[i].CreatedAt = formatDateTimeDisplay(payload.Compensations[i].CreatedAt)
	}
	return payload.Compensations, nil
}

func (s *server) fetchLocationCandidateValues(r *http.Request, number string) ([]candidateValueView, error) {
	apiReq, err := http.NewRequestWithContext(
		r.Context(),
		http.MethodGet,
		s.apiBaseURL+"/api/admin/locations/"+url.PathEscape(number)+"/candidate-values",
		nil,
	)
	if err != nil {
		return nil, err
	}
	copySessionCookieHeader(r, apiReq)
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		return nil, err
	}
	defer apiResp.Body.Close()
	if apiResp.StatusCode != http.StatusOK {
		return nil, errors.New("failed to fetch candidate values")
	}
	var payload candidateValuesResponse
	if err := json.NewDecoder(apiResp.Body).Decode(&payload); err != nil {
		return nil, err
	}
	for i := range payload.Values {
		normalizeCandidateValueView(&payload.Values[i])
	}
	return payload.Values, nil
}

func (s *server) fetchLocationCandidateInterviewNames(r *http.Request, number string) ([]candidateInterviewNameView, error) {
	apiReq, err := http.NewRequestWithContext(
		r.Context(),
		http.MethodGet,
		s.apiBaseURL+"/api/admin/locations/"+url.PathEscape(number)+"/candidate-interview-names",
		nil,
	)
	if err != nil {
		return nil, err
	}
	copySessionCookieHeader(r, apiReq)
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		return nil, err
	}
	defer apiResp.Body.Close()
	if apiResp.StatusCode != http.StatusOK {
		return nil, errors.New("failed to fetch candidate interview types")
	}
	var payload candidateInterviewNamesResponse
	if err := json.NewDecoder(apiResp.Body).Decode(&payload); err != nil {
		return nil, err
	}
	for i := range payload.Names {
		normalizeCandidateInterviewNameView(&payload.Names[i])
	}
	return payload.Names, nil
}

func (s *server) fetchLocationCandidateInterviewQuestions(r *http.Request, number string) ([]candidateInterviewQuestionView, error) {
	apiReq, err := http.NewRequestWithContext(
		r.Context(),
		http.MethodGet,
		s.apiBaseURL+"/api/admin/locations/"+url.PathEscape(number)+"/candidate-interview-questions",
		nil,
	)
	if err != nil {
		return nil, err
	}
	copySessionCookieHeader(r, apiReq)
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		return nil, err
	}
	defer apiResp.Body.Close()
	if apiResp.StatusCode != http.StatusOK {
		return nil, errors.New("failed to fetch candidate interview questions")
	}
	var payload candidateInterviewQuestionsResponse
	if err := json.NewDecoder(apiResp.Body).Decode(&payload); err != nil {
		return nil, err
	}
	for i := range payload.Questions {
		normalizeCandidateInterviewQuestionView(&payload.Questions[i])
	}
	return payload.Questions, nil
}

func (s *server) fetchCandidateInterviewLinks(r *http.Request, number string, candidateID int64) ([]candidateInterviewLinkView, error) {
	apiReq, err := http.NewRequestWithContext(
		r.Context(),
		http.MethodGet,
		s.apiBaseURL+"/api/admin/locations/"+url.PathEscape(number)+"/candidates/"+strconv.FormatInt(candidateID, 10)+"/interview-links",
		nil,
	)
	if err != nil {
		return nil, err
	}
	copySessionCookieHeader(r, apiReq)
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		return nil, err
	}
	defer apiResp.Body.Close()
	if apiResp.StatusCode != http.StatusOK {
		return nil, errors.New("failed to fetch candidate interview links")
	}
	var payload candidateInterviewLinksResponse
	if err := json.NewDecoder(apiResp.Body).Decode(&payload); err != nil {
		return nil, err
	}
	for i := range payload.Links {
		normalizeCandidateInterviewLinkView(&payload.Links[i])
	}
	return payload.Links, nil
}

func (s *server) fetchLocationInterviewCalendar(r *http.Request, number string) ([]interviewCalendarEntryView, error) {
	apiReq, err := http.NewRequestWithContext(
		r.Context(),
		http.MethodGet,
		s.apiBaseURL+"/api/admin/locations/"+url.PathEscape(number)+"/candidate-interview-calendar",
		nil,
	)
	if err != nil {
		return nil, err
	}
	copySessionCookieHeader(r, apiReq)
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		return nil, err
	}
	defer apiResp.Body.Close()
	if apiResp.StatusCode != http.StatusOK {
		return nil, errors.New("failed to fetch interview calendar")
	}
	var payload interviewCalendarResponse
	if err := json.NewDecoder(apiResp.Body).Decode(&payload); err != nil {
		return nil, err
	}
	return payload.Calendar, nil
}

func (s *server) fetchCandidateInterviewLink(r *http.Request, number string, candidateID int64, token string) (*candidateInterviewLinkView, error) {
	apiReq, err := http.NewRequestWithContext(
		r.Context(),
		http.MethodGet,
		s.apiBaseURL+"/api/admin/locations/"+url.PathEscape(number)+"/candidates/"+strconv.FormatInt(candidateID, 10)+"/interview-links/"+url.PathEscape(token),
		nil,
	)
	if err != nil {
		return nil, err
	}
	copySessionCookieHeader(r, apiReq)
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		return nil, err
	}
	defer apiResp.Body.Close()
	if apiResp.StatusCode != http.StatusOK {
		return nil, errors.New("failed to fetch candidate interview link")
	}
	var payload candidateInterviewLinkResponse
	if err := json.NewDecoder(apiResp.Body).Decode(&payload); err != nil {
		return nil, err
	}
	normalizeCandidateInterviewLinkView(&payload.Link)
	return &payload.Link, nil
}

func (s *server) fetchLocationCandidates(r *http.Request, number string, archived bool, search string) ([]candidateView, error) {
	apiURL := s.apiBaseURL + "/api/admin/locations/" + url.PathEscape(number) + "/candidates?archived=" + strconv.FormatBool(archived)
	if strings.TrimSpace(search) != "" {
		apiURL += "&search=" + url.QueryEscape(strings.TrimSpace(search))
	}
	apiReq, err := http.NewRequestWithContext(
		r.Context(),
		http.MethodGet,
		apiURL,
		nil,
	)
	if err != nil {
		return nil, err
	}
	copySessionCookieHeader(r, apiReq)
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		return nil, err
	}
	defer apiResp.Body.Close()
	if apiResp.StatusCode != http.StatusOK {
		return nil, errors.New("failed to fetch candidates")
	}
	var payload candidatesResponse
	if err := json.NewDecoder(apiResp.Body).Decode(&payload); err != nil {
		return nil, err
	}
	for i := range payload.Candidates {
		normalizeCandidateView(&payload.Candidates[i])
	}
	return payload.Candidates, nil
}

func (s *server) fetchLocationCandidate(r *http.Request, number string, candidateID int64) (*candidateView, error) {
	apiReq, err := http.NewRequestWithContext(
		r.Context(),
		http.MethodGet,
		s.apiBaseURL+"/api/admin/locations/"+url.PathEscape(number)+"/candidates/"+strconv.FormatInt(candidateID, 10)+"/scorecard",
		nil,
	)
	if err != nil {
		return nil, err
	}
	copySessionCookieHeader(r, apiReq)
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		return nil, err
	}
	defer apiResp.Body.Close()
	if apiResp.StatusCode != http.StatusOK {
		return nil, errors.New("failed to fetch candidate")
	}
	var payload candidateDetailResponse
	if err := json.NewDecoder(apiResp.Body).Decode(&payload); err != nil {
		return nil, err
	}
	normalizeCandidateView(&payload.Candidate)
	return &payload.Candidate, nil
}

func (s *server) fetchEmployeeCandidateScorecards(r *http.Request, locationNumber, timePunchName string) ([]candidateView, error) {
	apiReq, err := http.NewRequestWithContext(
		r.Context(),
		http.MethodGet,
		s.apiBaseURL+"/api/admin/locations/"+url.PathEscape(locationNumber)+"/employees/"+url.PathEscape(timePunchName)+"/scorecards",
		nil,
	)
	if err != nil {
		return nil, err
	}
	copySessionCookieHeader(r, apiReq)
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		return nil, err
	}
	defer apiResp.Body.Close()
	if apiResp.StatusCode != http.StatusOK {
		return nil, errors.New("failed to fetch employee scorecards")
	}
	var payload candidatesResponse
	if err := json.NewDecoder(apiResp.Body).Decode(&payload); err != nil {
		return nil, err
	}
	for i := range payload.Candidates {
		normalizeCandidateView(&payload.Candidates[i])
	}
	return payload.Candidates, nil
}

func (s *server) fetchArchivedLocationEmployees(r *http.Request, number string) ([]employeeView, error) {
	apiReq, err := http.NewRequestWithContext(
		r.Context(),
		http.MethodGet,
		s.apiBaseURL+"/api/admin/locations/"+url.PathEscape(number)+"/employees/archived",
		nil,
	)
	if err != nil {
		return nil, err
	}
	copySessionCookieHeader(r, apiReq)
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		return nil, err
	}
	defer apiResp.Body.Close()
	if apiResp.StatusCode != http.StatusOK {
		return nil, errors.New("failed to fetch archived employees")
	}
	var payload locationEmployeesResponse
	if err := json.NewDecoder(apiResp.Body).Decode(&payload); err != nil {
		return nil, err
	}
	for i := range payload.Employees {
		normalizeEmployeeView(&payload.Employees[i])
	}
	return payload.Employees, nil
}

func (s *server) fetchLocationTimePunchEntries(r *http.Request, number string, archived bool) ([]timePunchEntryView, error) {
	apiURL := s.apiBaseURL + "/api/admin/locations/" + url.PathEscape(number) + "/time-punch"
	if archived {
		apiURL += "?archived=1"
	}
	apiReq, err := http.NewRequestWithContext(
		r.Context(),
		http.MethodGet,
		apiURL,
		nil,
	)
	if err != nil {
		return nil, err
	}
	copySessionCookieHeader(r, apiReq)
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		return nil, err
	}
	defer apiResp.Body.Close()
	if apiResp.StatusCode != http.StatusOK {
		return nil, errors.New("failed to fetch time punch entries")
	}
	var payload timePunchEntriesResponse
	if err := json.NewDecoder(apiResp.Body).Decode(&payload); err != nil {
		return nil, err
	}
	for i := range payload.Entries {
		payload.Entries[i].TimeIn = formatPunchClockDisplay(payload.Entries[i].TimeIn)
		payload.Entries[i].TimeOut = formatPunchClockDisplay(payload.Entries[i].TimeOut)
		payload.Entries[i].CreatedAt = formatDateTimeDisplay(payload.Entries[i].CreatedAt)
		if archived {
			payload.Entries[i].ArchivedAt = formatDateTimeDisplay(payload.Entries[i].ArchivedAt)
		} else {
			payload.Entries[i].ArchivedAt = ""
		}
	}
	return payload.Entries, nil
}

func limitTimePunchEntries(entries []timePunchEntryView, limit int) []timePunchEntryView {
	if limit <= 0 || len(entries) <= limit {
		return entries
	}
	return entries[:limit]
}

func (s *server) fetchLocationTimePunchToken(r *http.Request, number string) (string, error) {
	apiReq, err := http.NewRequestWithContext(
		r.Context(),
		http.MethodGet,
		s.apiBaseURL+"/api/admin/locations/"+url.PathEscape(number)+"/time-punch/link",
		nil,
	)
	if err != nil {
		return "", err
	}
	copySessionCookieHeader(r, apiReq)
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		return "", err
	}
	defer apiResp.Body.Close()
	if apiResp.StatusCode != http.StatusOK {
		return "", errors.New("failed to fetch time punch token")
	}
	var payload timePunchLinkResponse
	if err := json.NewDecoder(apiResp.Body).Decode(&payload); err != nil {
		return "", err
	}
	if strings.TrimSpace(payload.Token) == "" {
		return "", errors.New("empty time punch token")
	}
	return payload.Token, nil
}

func (s *server) fetchLocationTimeOffRequests(r *http.Request, number string, archived bool) ([]timeOffRequestView, error) {
	apiURL := s.apiBaseURL + "/api/admin/locations/" + url.PathEscape(number) + "/time-off"
	if archived {
		apiURL += "?archived=1"
	}
	apiReq, err := http.NewRequestWithContext(
		r.Context(),
		http.MethodGet,
		apiURL,
		nil,
	)
	if err != nil {
		return nil, err
	}
	copySessionCookieHeader(r, apiReq)
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		return nil, err
	}
	defer apiResp.Body.Close()
	if apiResp.StatusCode != http.StatusOK {
		return nil, errors.New("failed to fetch time off requests")
	}
	var payload timeOffRequestsResponse
	if err := json.NewDecoder(apiResp.Body).Decode(&payload); err != nil {
		return nil, err
	}
	for i := range payload.Requests {
		payload.Requests[i].CreatedAt = formatDateTimeDisplay(payload.Requests[i].CreatedAt)
		payload.Requests[i].ArchivedAt = formatDateTimeDisplay(payload.Requests[i].ArchivedAt)
	}
	return payload.Requests, nil
}

func (s *server) fetchLocationTimeOffToken(r *http.Request, number string) (string, error) {
	apiReq, err := http.NewRequestWithContext(
		r.Context(),
		http.MethodGet,
		s.apiBaseURL+"/api/admin/locations/"+url.PathEscape(number)+"/time-off/link",
		nil,
	)
	if err != nil {
		return "", err
	}
	copySessionCookieHeader(r, apiReq)
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		return "", err
	}
	defer apiResp.Body.Close()
	if apiResp.StatusCode != http.StatusOK {
		return "", errors.New("failed to fetch time off token")
	}
	var payload timePunchLinkResponse
	if err := json.NewDecoder(apiResp.Body).Decode(&payload); err != nil {
		return "", err
	}
	if strings.TrimSpace(payload.Token) == "" {
		return "", errors.New("empty time off token")
	}
	return payload.Token, nil
}

func (s *server) fetchLocationUniformToken(r *http.Request, number string) (string, error) {
	apiReq, err := http.NewRequestWithContext(
		r.Context(),
		http.MethodGet,
		s.apiBaseURL+"/api/admin/locations/"+url.PathEscape(number)+"/uniform-order/link",
		nil,
	)
	if err != nil {
		return "", err
	}
	copySessionCookieHeader(r, apiReq)
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		return "", err
	}
	defer apiResp.Body.Close()
	if apiResp.StatusCode != http.StatusOK {
		return "", errors.New("failed to fetch uniform token")
	}
	var payload uniformLinkResponse
	if err := json.NewDecoder(apiResp.Body).Decode(&payload); err != nil {
		return "", err
	}
	if strings.TrimSpace(payload.Token) == "" {
		return "", errors.New("empty uniform token")
	}
	return payload.Token, nil
}

func (s *server) fetchLocationUniformItems(r *http.Request, number string) ([]uniformItemView, error) {
	apiReq, err := http.NewRequestWithContext(
		r.Context(),
		http.MethodGet,
		s.apiBaseURL+"/api/admin/locations/"+url.PathEscape(number)+"/uniform-items",
		nil,
	)
	if err != nil {
		return nil, err
	}
	copySessionCookieHeader(r, apiReq)
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		return nil, err
	}
	defer apiResp.Body.Close()
	if apiResp.StatusCode != http.StatusOK {
		return nil, errors.New("failed to fetch uniform items")
	}
	var payload uniformItemsResponse
	if err := json.NewDecoder(apiResp.Body).Decode(&payload); err != nil {
		return nil, err
	}
	return payload.Items, nil
}

func (s *server) fetchLocationUniformOrders(r *http.Request, number string, archived bool) ([]uniformOrderView, error) {
	apiURL := s.apiBaseURL + "/api/admin/locations/" + url.PathEscape(number) + "/uniform-orders"
	if archived {
		apiURL += "?archived=1"
	}
	apiReq, err := http.NewRequestWithContext(
		r.Context(),
		http.MethodGet,
		apiURL,
		nil,
	)
	if err != nil {
		return nil, err
	}
	copySessionCookieHeader(r, apiReq)
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		return nil, err
	}
	defer apiResp.Body.Close()
	if apiResp.StatusCode != http.StatusOK {
		return nil, errors.New("failed to fetch uniform orders")
	}
	var payload uniformOrdersResponse
	if err := json.NewDecoder(apiResp.Body).Decode(&payload); err != nil {
		return nil, err
	}
	for i := range payload.Orders {
		payload.Orders[i].CreatedAt = formatDateTimeDisplay(payload.Orders[i].CreatedAt)
		payload.Orders[i].ArchivedAt = formatDateTimeDisplay(payload.Orders[i].ArchivedAt)
		for j := range payload.Orders[i].Lines {
			payload.Orders[i].Lines[j].PurchasedAt = formatDateTimeDisplay(payload.Orders[i].Lines[j].PurchasedAt)
		}
		payload.Orders[i].Status = uniformOrderStatus(payload.Orders[i])
	}
	return payload.Orders, nil
}

func (s *server) fetchLocationUniformItem(r *http.Request, number string, itemID int64) (*uniformItemView, error) {
	apiReq, err := http.NewRequestWithContext(
		r.Context(),
		http.MethodGet,
		s.apiBaseURL+"/api/admin/locations/"+url.PathEscape(number)+"/uniform-items/"+strconv.FormatInt(itemID, 10),
		nil,
	)
	if err != nil {
		return nil, err
	}
	copySessionCookieHeader(r, apiReq)
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		return nil, err
	}
	defer apiResp.Body.Close()
	if apiResp.StatusCode != http.StatusOK {
		return nil, errors.New("failed to fetch uniform item")
	}
	var payload uniformItemDetailResponse
	if err := json.NewDecoder(apiResp.Body).Decode(&payload); err != nil {
		return nil, err
	}
	return &payload.Item, nil
}

func (s *server) fetchLocationBusinessDays(r *http.Request, number string) ([]businessDayView, error) {
	apiReq, err := http.NewRequestWithContext(
		r.Context(),
		http.MethodGet,
		s.apiBaseURL+"/api/admin/locations/"+url.PathEscape(number)+"/business-days",
		nil,
	)
	if err != nil {
		return nil, err
	}
	copySessionCookieHeader(r, apiReq)
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		return nil, err
	}
	defer apiResp.Body.Close()
	if apiResp.StatusCode != http.StatusOK {
		return nil, errors.New("failed to fetch business days")
	}
	var payload businessDaysResponse
	if err := json.NewDecoder(apiResp.Body).Decode(&payload); err != nil {
		return nil, err
	}
	for i := range payload.BusinessDays {
		payload.BusinessDays[i].CreatedAt = formatDateTimeDisplay(payload.BusinessDays[i].CreatedAt)
	}
	return payload.BusinessDays, nil
}

func (s *server) fetchOrCreateBusinessDay(r *http.Request, locationNumber, businessDate string) (*businessDayView, error) {
	apiReq, err := http.NewRequestWithContext(
		r.Context(),
		http.MethodGet,
		s.apiBaseURL+"/api/admin/locations/"+url.PathEscape(locationNumber)+"/business-days/"+url.PathEscape(businessDate),
		nil,
	)
	if err != nil {
		return nil, err
	}
	copySessionCookieHeader(r, apiReq)
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		return nil, err
	}
	defer apiResp.Body.Close()
	if apiResp.StatusCode != http.StatusOK {
		return nil, errors.New("failed to fetch business day")
	}
	var payload businessDayResponse
	if err := json.NewDecoder(apiResp.Body).Decode(&payload); err != nil {
		return nil, err
	}
	payload.BusinessDay.CreatedAt = formatDateTimeDisplay(payload.BusinessDay.CreatedAt)
	return &payload.BusinessDay, nil
}

func (s *server) fetchEmployee(r *http.Request, locationNumber, timePunchName string) (*employeeView, error) {
	apiReq, err := http.NewRequestWithContext(
		r.Context(),
		http.MethodGet,
		s.apiBaseURL+"/api/admin/locations/"+url.PathEscape(locationNumber)+"/employees/"+url.PathEscape(timePunchName),
		nil,
	)
	if err != nil {
		return nil, err
	}
	copySessionCookieHeader(r, apiReq)
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		return nil, err
	}
	defer apiResp.Body.Close()
	if apiResp.StatusCode != http.StatusOK {
		return nil, errors.New("employee not found")
	}
	var payload employeeDetailResponse
	if err := json.NewDecoder(apiResp.Body).Decode(&payload); err != nil {
		return nil, err
	}
	normalizeEmployeeView(&payload.Employee)
	return &payload.Employee, nil
}

func (s *server) fetchArchivedEmployee(r *http.Request, locationNumber, timePunchName string) (*employeeView, error) {
	apiReq, err := http.NewRequestWithContext(
		r.Context(),
		http.MethodGet,
		s.apiBaseURL+"/api/admin/locations/"+url.PathEscape(locationNumber)+"/employees/archived/"+url.PathEscape(timePunchName),
		nil,
	)
	if err != nil {
		return nil, err
	}
	copySessionCookieHeader(r, apiReq)
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		return nil, err
	}
	defer apiResp.Body.Close()
	if apiResp.StatusCode != http.StatusOK {
		return nil, errors.New("employee not found")
	}
	var payload employeeDetailResponse
	if err := json.NewDecoder(apiResp.Body).Decode(&payload); err != nil {
		return nil, err
	}
	normalizeEmployeeView(&payload.Employee)
	return &payload.Employee, nil
}

func (s *server) fetchEmployeePaperwork(r *http.Request, locationNumber, timePunchName string, archived bool, paperworkType string) (*employeeI9View, []employeeI9DocumentView, []paperworkHistoryView, error) {
	apiURL := s.apiBaseURL + "/api/admin/locations/" + url.PathEscape(locationNumber)
	if archived {
		apiURL += "/employees/archived/" + url.PathEscape(timePunchName) + "/" + url.PathEscape(strings.ToLower(strings.TrimSpace(paperworkType)))
	} else {
		apiURL += "/employees/" + url.PathEscape(timePunchName) + "/" + url.PathEscape(strings.ToLower(strings.TrimSpace(paperworkType)))
	}
	apiReq, err := http.NewRequestWithContext(r.Context(), http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, nil, nil, err
	}
	copySessionCookieHeader(r, apiReq)
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		return nil, nil, nil, err
	}
	defer apiResp.Body.Close()
	if apiResp.StatusCode != http.StatusOK {
		return nil, nil, nil, errors.New("failed to fetch employee paperwork records")
	}
	var payload employeePaperworkResponse
	if err := json.NewDecoder(apiResp.Body).Decode(&payload); err != nil {
		return nil, nil, nil, err
	}
	normalizeEmployeePaperworkView(&payload.Paperwork)
	for i := range payload.Documents {
		payload.Documents[i].CreatedAt = formatDateTimeDisplay(payload.Documents[i].CreatedAt)
	}
	for i := range payload.History {
		payload.History[i].CreatedAt = formatDateTimeDisplay(payload.History[i].CreatedAt)
	}
	return &payload.Paperwork, payload.Documents, payload.History, nil
}

func buildTeamDocumentsFromPaperwork(paperworkType string, form *employeeI9View, i9Docs []employeeI9DocumentView, history []paperworkHistoryView) []teamDocumentView {
	documents := make([]teamDocumentView, 0, 8)
	isW4 := strings.EqualFold(strings.TrimSpace(paperworkType), "w4")
	if form != nil && form.HasFile {
		label := "Current I-9 Form"
		downloadPath := "/team/documents/i9/file"
		category := "i9_form"
		if isW4 {
			label = "Current W-4 Form"
			downloadPath = "/team/documents/w4/file"
			category = "w4_form"
		}
		created := strings.TrimSpace(form.UpdatedAt)
		if created == "" {
			created = strings.TrimSpace(form.CreatedAt)
		}
		documents = append(documents, teamDocumentView{
			Label:        label,
			Category:     category,
			CreatedAt:    created,
			DownloadPath: downloadPath,
		})
	}
	for _, historyItem := range history {
		if historyItem.ID <= 0 {
			continue
		}
		label := "I-9 Form History"
		category := "i9_history"
		downloadPath := "/team/documents/i9/file?version_id=" + strconv.FormatInt(historyItem.ID, 10)
		if isW4 {
			label = "W-4 Form History"
			category = "w4_history"
			downloadPath = "/team/documents/w4/file?version_id=" + strconv.FormatInt(historyItem.ID, 10)
		}
		documents = append(documents, teamDocumentView{
			Label:        label,
			Category:     category,
			CreatedAt:    strings.TrimSpace(historyItem.CreatedAt),
			DownloadPath: downloadPath,
		})
	}
	for _, doc := range i9Docs {
		if doc.ID <= 0 {
			continue
		}
		label := strings.TrimSpace(doc.FileName)
		if label == "" {
			label = "I-9 Supporting Document"
		}
		documents = append(documents, teamDocumentView{
			Label:        label,
			Category:     "i9_supporting",
			CreatedAt:    strings.TrimSpace(doc.CreatedAt),
			DownloadPath: "/team/documents/i9/supporting/" + strconv.FormatInt(doc.ID, 10) + "/file",
		})
	}
	sort.SliceStable(documents, func(i, j int) bool {
		return strings.ToLower(strings.TrimSpace(documents[i].CreatedAt)) > strings.ToLower(strings.TrimSpace(documents[j].CreatedAt))
	})
	return documents
}

func normalizeLocationView(location *locationView) {
	location.CreatedAt = formatDateTimeDisplay(location.CreatedAt)
}

func normalizeEmployeeView(employee *employeeView) {
	employee.Birthday = formatBirthdayDisplay(employee.Birthday)
	employee.ArchivedAt = formatDateTimeDisplay(employee.ArchivedAt)
}

func normalizeEmployeePaperworkView(paperwork *employeeI9View) {
	paperwork.CreatedAt = formatDateTimeDisplay(paperwork.CreatedAt)
	paperwork.UpdatedAt = formatDateTimeDisplay(paperwork.UpdatedAt)
}

func normalizeCandidateValueView(value *candidateValueView) {
	value.CreatedAt = formatDateTimeDisplay(value.CreatedAt)
	value.UpdatedAt = formatDateTimeDisplay(value.UpdatedAt)
}

func normalizeCandidateInterviewNameView(name *candidateInterviewNameView) {
	name.CreatedAt = formatDateTimeDisplay(name.CreatedAt)
	name.UpdatedAt = formatDateTimeDisplay(name.UpdatedAt)
}

func normalizeCandidateInterviewQuestionView(question *candidateInterviewQuestionView) {
	question.ResponseType = strings.ToLower(strings.TrimSpace(question.ResponseType))
	if question.ResponseType == "" {
		question.ResponseType = "text"
	}
	question.ResponseKind = question.ResponseType
	normalizedOptions := make([]string, 0, len(question.ResponseOptions))
	seen := make(map[string]struct{}, len(question.ResponseOptions))
	for _, raw := range question.ResponseOptions {
		option := strings.TrimSpace(raw)
		if option == "" {
			continue
		}
		key := strings.ToLower(option)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		normalizedOptions = append(normalizedOptions, option)
	}
	question.ResponseOptions = normalizedOptions
	if question.ResponseType == "multiple_choice" && len(normalizedOptions) == 2 {
		first := strings.ToLower(strings.TrimSpace(normalizedOptions[0]))
		second := strings.ToLower(strings.TrimSpace(normalizedOptions[1]))
		if first == "yes" && second == "no" {
			question.ResponseKind = "yes_no"
		} else if first == "true" && second == "false" {
			question.ResponseKind = "true_false"
		}
	}
	question.ResponseOptionsText = strings.Join(normalizedOptions, "\n")
	question.CreatedAt = formatDateTimeDisplay(question.CreatedAt)
	question.UpdatedAt = formatDateTimeDisplay(question.UpdatedAt)
}

func normalizeCandidateInterviewLinkView(link *candidateInterviewLinkView) {
	link.ScheduledAt = formatDateTimeDisplay(link.ScheduledAt)
	link.CreatedAt = formatDateTimeDisplay(link.CreatedAt)
	link.ExpiresAt = formatDateTimeDisplay(link.ExpiresAt)
	link.UsedAt = formatDateTimeDisplay(link.UsedAt)
}

func normalizeInterviewCalendarEntryView(entry *interviewCalendarEntryView) {
	entry.ScheduledAt = formatDateTimeDisplay(entry.ScheduledAt)
	entry.CreatedAt = formatDateTimeDisplay(entry.CreatedAt)
	entry.UsedAt = formatDateTimeDisplay(entry.UsedAt)
}

func normalizeCandidateInterviewView(interview *candidateInterviewView) {
	interview.CreatedAt = formatDateTimeDisplay(interview.CreatedAt)
}

func normalizeCandidateView(candidate *candidateView) {
	candidate.CreatedAt = formatDateTimeDisplay(candidate.CreatedAt)
	candidate.UpdatedAt = formatDateTimeDisplay(candidate.UpdatedAt)
	candidate.ArchivedAt = formatDateTimeDisplay(candidate.ArchivedAt)
	for i := range candidate.Interviews {
		normalizeCandidateInterviewView(&candidate.Interviews[i])
	}
}

func formatBirthdayDisplay(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}
	formats := []string{
		"2006-01-02",
		"1/2/2006",
		"01/02/2006",
		"1/2/06",
		"01/02/06",
		"1-2-2006",
		"01-02-2006",
		"2006/01/02",
		"Jan 2, 2006",
		"January 2, 2006",
		"2 Jan 2006",
		"2 January 2006",
		"2006-01-02 15:04:05",
		time.RFC3339,
		time.RFC3339Nano,
	}
	// Excel numeric serial value support for display resilience.
	if serial, err := strconv.ParseFloat(trimmed, 64); err == nil {
		if serial >= 20000 && serial <= 80000 {
			if parsed, err := excelize.ExcelDateToTime(serial, false); err == nil {
				return parsed.Format("01/02/2006")
			}
		}
	}
	for _, layout := range formats {
		if parsed, err := time.Parse(layout, trimmed); err == nil {
			return parsed.Format("01/02/2006")
		}
	}
	return trimmed
}

func formatDateTimeDisplay(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}
	dateOnlyLayouts := []string{
		"2006-01-02",
		"1/2/2006",
		"01/02/2006",
		"1-2-2006",
		"01-02-2006",
		"2006/01/02",
		"Jan 2, 2006",
		"January 2, 2006",
		"2 Jan 2006",
		"2 January 2006",
	}
	for _, layout := range dateOnlyLayouts {
		if parsed, err := time.Parse(layout, trimmed); err == nil {
			return parsed.Format("Jan 2, 2006")
		}
	}
	dateTimeLayouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05",
		"2006-01-02 15:04",
		"2006-01-02T15:04:05",
		"2006-01-02T15:04",
	}
	for _, layout := range dateTimeLayouts {
		if parsed, err := time.Parse(layout, trimmed); err == nil {
			return parsed.Local().Format("Jan 2, 2006 3:04 PM")
		}
	}
	return trimmed
}

func formatPunchClockDisplay(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}
	layouts := []string{"15:04", "15:04:05", "3:04 PM", "3:04PM"}
	for _, layout := range layouts {
		if parsed, err := time.Parse(layout, trimmed); err == nil {
			return parsed.Format("3:04 PM")
		}
	}
	return trimmed
}

func sessionRoleFromUser(user *authSessionView) string {
	if user == nil {
		return ""
	}
	role := strings.ToLower(strings.TrimSpace(user.Role))
	switch role {
	case "admin":
		return "admin"
	case "restaurant":
		return "restaurant"
	case "team":
		return "team"
	default:
		return ""
	}
}

func cookieNameForSessionRole(role string) string {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case "admin":
		return adminSessionCookie
	case "restaurant":
		return restaurantSessionCookie
	case "team":
		return teamSessionCookie
	default:
		return ""
	}
}

func chooseAPISessionValue(from *http.Request) string {
	path := from.URL.Path
	if strings.HasPrefix(path, "/team") || strings.HasPrefix(path, "/team-login") {
		if cookie, err := from.Cookie(teamSessionCookie); err == nil && strings.TrimSpace(cookie.Value) != "" {
			return strings.TrimSpace(cookie.Value)
		}
	}
	if strings.HasPrefix(path, "/admin") || strings.HasPrefix(path, "/logout") || strings.HasPrefix(path, "/login") || path == "/" {
		if cookie, err := from.Cookie(adminSessionCookie); err == nil && strings.TrimSpace(cookie.Value) != "" {
			return strings.TrimSpace(cookie.Value)
		}
		if cookie, err := from.Cookie(restaurantSessionCookie); err == nil && strings.TrimSpace(cookie.Value) != "" {
			return strings.TrimSpace(cookie.Value)
		}
		if cookie, err := from.Cookie(teamSessionCookie); err == nil && strings.TrimSpace(cookie.Value) != "" {
			return strings.TrimSpace(cookie.Value)
		}
	}
	if cookie, err := from.Cookie(adminSessionCookie); err == nil && strings.TrimSpace(cookie.Value) != "" {
		return strings.TrimSpace(cookie.Value)
	}
	if cookie, err := from.Cookie(restaurantSessionCookie); err == nil && strings.TrimSpace(cookie.Value) != "" {
		return strings.TrimSpace(cookie.Value)
	}
	if cookie, err := from.Cookie(teamSessionCookie); err == nil && strings.TrimSpace(cookie.Value) != "" {
		return strings.TrimSpace(cookie.Value)
	}
	return ""
}

func copySessionCookieHeader(from *http.Request, to *http.Request) {
	sessionValue := chooseAPISessionValue(from)
	if sessionValue == "" {
		return
	}
	to.Header.Set("Cookie", apiSessionCookie+"="+sessionValue)
}

func copySessionCookieHeaderForValue(to *http.Request, sessionValue string) {
	sessionValue = strings.TrimSpace(sessionValue)
	if sessionValue == "" {
		return
	}
	to.Header.Set("Cookie", apiSessionCookie+"="+sessionValue)
}

func extractAPISessionCookieValue(resp *http.Response) string {
	if resp == nil {
		return ""
	}
	for _, c := range resp.Cookies() {
		if c.Name == apiSessionCookie && strings.TrimSpace(c.Value) != "" {
			return strings.TrimSpace(c.Value)
		}
	}
	return ""
}

func setScopedSessionCookie(w http.ResponseWriter, cookieName, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

func expireSessionCookieByName(w http.ResponseWriter, cookieName string) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func expireSessionCookie(w http.ResponseWriter) {
	expireSessionCookieByName(w, adminSessionCookie)
	expireSessionCookieByName(w, restaurantSessionCookie)
	expireSessionCookieByName(w, teamSessionCookie)
}

func renderHTMLTemplate(w http.ResponseWriter, tmpl *template.Template, data pageData) error {
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, err := w.Write(buf.Bytes())
	return err
}

func envOrDefault(name, fallback string) string {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	return value
}

func parsePositiveInt(raw string, fallback int) int {
	value, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || value <= 0 {
		return fallback
	}
	return value
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func locationNumberFromAdminPath(path string) (string, bool) {
	trimmed := strings.TrimPrefix(path, "/admin/locations/")
	trimmed = strings.Trim(trimmed, "/")
	if trimmed == "" || strings.Contains(trimmed, "/") {
		return "", false
	}
	number, err := url.PathUnescape(trimmed)
	if err != nil || strings.TrimSpace(number) == "" {
		return "", false
	}
	return number, true
}

func normalizeDepartments(values []string) []string {
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

func parseLocationEmployeePath(path string) (string, string, bool) {
	trimmed := strings.TrimPrefix(path, "/admin/locations/")
	trimmed = strings.Trim(trimmed, "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) != 3 || parts[1] != "employees" {
		return "", "", false
	}
	locationNumber, err := url.PathUnescape(parts[0])
	if err != nil || strings.TrimSpace(locationNumber) == "" {
		return "", "", false
	}
	timePunchName, err := url.PathUnescape(parts[2])
	if err != nil || strings.TrimSpace(timePunchName) == "" {
		return "", "", false
	}
	return locationNumber, timePunchName, true
}

func parseArchivedLocationEmployeesPath(path string) (string, bool) {
	trimmed := strings.TrimPrefix(path, "/admin/locations/")
	trimmed = strings.Trim(trimmed, "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) != 3 || parts[1] != "employees" || parts[2] != "archived" {
		return "", false
	}
	locationNumber, err := url.PathUnescape(parts[0])
	if err != nil || strings.TrimSpace(locationNumber) == "" {
		return "", false
	}
	return locationNumber, true
}

func parseArchivedLocationEmployeePath(path string) (string, string, bool) {
	trimmed := strings.TrimPrefix(path, "/admin/locations/")
	trimmed = strings.Trim(trimmed, "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) != 4 || parts[1] != "employees" || parts[2] != "archived" {
		return "", "", false
	}
	locationNumber, err := url.PathUnescape(parts[0])
	if err != nil || strings.TrimSpace(locationNumber) == "" {
		return "", "", false
	}
	timePunchName, err := url.PathUnescape(parts[3])
	if err != nil || strings.TrimSpace(timePunchName) == "" {
		return "", "", false
	}
	return locationNumber, timePunchName, true
}

func parseLocationEmployeesPath(path string) (string, bool) {
	trimmed := strings.TrimPrefix(path, "/admin/locations/")
	trimmed = strings.Trim(trimmed, "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) != 2 || parts[1] != "employees" {
		return "", false
	}
	locationNumber, err := url.PathUnescape(parts[0])
	if err != nil || strings.TrimSpace(locationNumber) == "" {
		return "", false
	}
	return locationNumber, true
}

func parseLocationCandidatesPath(path string) (string, bool) {
	trimmed := strings.TrimPrefix(path, "/admin/locations/")
	trimmed = strings.Trim(trimmed, "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) != 2 || parts[1] != "candidates" {
		return "", false
	}
	locationNumber, err := url.PathUnescape(parts[0])
	if err != nil || strings.TrimSpace(locationNumber) == "" {
		return "", false
	}
	return locationNumber, true
}

func parseLocationInterviewProcessPath(path string) (string, bool) {
	trimmed := strings.TrimPrefix(path, "/admin/locations/")
	trimmed = strings.Trim(trimmed, "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) != 2 || parts[1] != "interview-process" {
		return "", false
	}
	locationNumber, err := url.PathUnescape(parts[0])
	if err != nil || strings.TrimSpace(locationNumber) == "" {
		return "", false
	}
	return locationNumber, true
}

func parseLocationCandidatesCreatePath(path string) (string, bool) {
	return parseLocationCandidatesPath(path)
}

func parseLocationCandidateValuesCreatePath(path string) (string, bool) {
	trimmed := strings.TrimPrefix(path, "/admin/locations/")
	trimmed = strings.Trim(trimmed, "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) != 2 || parts[1] != "candidate-values" {
		return "", false
	}
	locationNumber, err := url.PathUnescape(parts[0])
	if err != nil || strings.TrimSpace(locationNumber) == "" {
		return "", false
	}
	return locationNumber, true
}

func parseLocationCandidateInterviewNamesCreatePath(path string) (string, bool) {
	trimmed := strings.TrimPrefix(path, "/admin/locations/")
	trimmed = strings.Trim(trimmed, "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) != 2 || parts[1] != "candidate-interview-names" {
		return "", false
	}
	locationNumber, err := url.PathUnescape(parts[0])
	if err != nil || strings.TrimSpace(locationNumber) == "" {
		return "", false
	}
	return locationNumber, true
}

func parseLocationCandidateInterviewQuestionsCreatePath(path string) (string, bool) {
	trimmed := strings.TrimPrefix(path, "/admin/locations/")
	trimmed = strings.Trim(trimmed, "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) != 2 || parts[1] != "candidate-interview-questions" {
		return "", false
	}
	locationNumber, err := url.PathUnescape(parts[0])
	if err != nil || strings.TrimSpace(locationNumber) == "" {
		return "", false
	}
	return locationNumber, true
}

func parseLocationCandidateInterviewQuestionStartersCreatePath(path string) (string, bool) {
	trimmed := strings.TrimPrefix(path, "/admin/locations/")
	trimmed = strings.Trim(trimmed, "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) != 3 || parts[1] != "candidate-interview-questions" || parts[2] != "starters" {
		return "", false
	}
	locationNumber, err := url.PathUnescape(parts[0])
	if err != nil || strings.TrimSpace(locationNumber) == "" {
		return "", false
	}
	return locationNumber, true
}

func parseLocationCandidateValueUpdatePath(path string) (string, int64, bool) {
	trimmed := strings.TrimPrefix(path, "/admin/locations/")
	trimmed = strings.Trim(trimmed, "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) != 3 || parts[1] != "candidate-values" {
		return "", 0, false
	}
	locationNumber, err := url.PathUnescape(parts[0])
	if err != nil || strings.TrimSpace(locationNumber) == "" {
		return "", 0, false
	}
	valueID, err := strconv.ParseInt(strings.TrimSpace(parts[2]), 10, 64)
	if err != nil || valueID <= 0 {
		return "", 0, false
	}
	return locationNumber, valueID, true
}

func parseLocationCandidateValueDeletePath(path string) (string, int64, bool) {
	trimmed := strings.TrimPrefix(path, "/admin/locations/")
	trimmed = strings.Trim(trimmed, "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) != 4 || parts[1] != "candidate-values" || parts[3] != "delete" {
		return "", 0, false
	}
	locationNumber, err := url.PathUnescape(parts[0])
	if err != nil || strings.TrimSpace(locationNumber) == "" {
		return "", 0, false
	}
	valueID, err := strconv.ParseInt(strings.TrimSpace(parts[2]), 10, 64)
	if err != nil || valueID <= 0 {
		return "", 0, false
	}
	return locationNumber, valueID, true
}

func parseLocationCandidateInterviewNameDeletePath(path string) (string, int64, bool) {
	trimmed := strings.TrimPrefix(path, "/admin/locations/")
	trimmed = strings.Trim(trimmed, "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) != 4 || parts[1] != "candidate-interview-names" || parts[3] != "delete" {
		return "", 0, false
	}
	locationNumber, err := url.PathUnescape(parts[0])
	if err != nil || strings.TrimSpace(locationNumber) == "" {
		return "", 0, false
	}
	nameID, err := strconv.ParseInt(strings.TrimSpace(parts[2]), 10, 64)
	if err != nil || nameID <= 0 {
		return "", 0, false
	}
	return locationNumber, nameID, true
}

func parseLocationCandidateInterviewNamePriorityPath(path string) (string, int64, bool) {
	trimmed := strings.TrimPrefix(path, "/admin/locations/")
	trimmed = strings.Trim(trimmed, "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) != 5 || parts[1] != "candidate-interview-names" || parts[3] != "priority" {
		return "", 0, false
	}
	locationNumber, err := url.PathUnescape(parts[0])
	if err != nil || strings.TrimSpace(locationNumber) == "" {
		return "", 0, false
	}
	nameID, err := strconv.ParseInt(strings.TrimSpace(parts[2]), 10, 64)
	if err != nil || nameID <= 0 {
		return "", 0, false
	}
	return locationNumber, nameID, true
}

func parseLocationCandidateInterviewNamesReorderPath(path string) (string, bool) {
	trimmed := strings.TrimPrefix(path, "/admin/locations/")
	trimmed = strings.Trim(trimmed, "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) != 3 || parts[1] != "candidate-interview-names" || parts[2] != "reorder" {
		return "", false
	}
	locationNumber, err := url.PathUnescape(parts[0])
	if err != nil || strings.TrimSpace(locationNumber) == "" {
		return "", false
	}
	return locationNumber, true
}

func parseLocationCandidateInterviewQuestionDeletePath(path string) (string, int64, bool) {
	trimmed := strings.TrimPrefix(path, "/admin/locations/")
	trimmed = strings.Trim(trimmed, "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) != 4 || parts[1] != "candidate-interview-questions" || parts[3] != "delete" {
		return "", 0, false
	}
	locationNumber, err := url.PathUnescape(parts[0])
	if err != nil || strings.TrimSpace(locationNumber) == "" {
		return "", 0, false
	}
	questionID, err := strconv.ParseInt(strings.TrimSpace(parts[2]), 10, 64)
	if err != nil || questionID <= 0 {
		return "", 0, false
	}
	return locationNumber, questionID, true
}

func parseLocationCandidateInterviewQuestionAssignPath(path string) (string, int64, bool) {
	trimmed := strings.TrimPrefix(path, "/admin/locations/")
	trimmed = strings.Trim(trimmed, "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) != 4 || parts[1] != "candidate-interview-questions" || parts[3] != "assign" {
		return "", 0, false
	}
	locationNumber, err := url.PathUnescape(parts[0])
	if err != nil || strings.TrimSpace(locationNumber) == "" {
		return "", 0, false
	}
	questionID, err := strconv.ParseInt(strings.TrimSpace(parts[2]), 10, 64)
	if err != nil || questionID <= 0 {
		return "", 0, false
	}
	return locationNumber, questionID, true
}

func parseInterviewTypeIDs(values []string) []int64 {
	seen := make(map[int64]struct{}, len(values))
	out := make([]int64, 0, len(values))
	for _, raw := range values {
		id, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
		if err != nil || id <= 0 {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func mergeInterviewTypeIDs(existing, incoming []int64) []int64 {
	seen := make(map[int64]struct{}, len(existing)+len(incoming))
	out := make([]int64, 0, len(existing)+len(incoming))
	for _, id := range existing {
		if id <= 0 {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	for _, id := range incoming {
		if id <= 0 {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func int64SlicesEqual(a, b []int64) bool {
	left := make([]int64, 0, len(a))
	right := make([]int64, 0, len(b))
	left = append(left, a...)
	right = append(right, b...)
	sort.Slice(left, func(i, j int) bool { return left[i] < left[j] })
	sort.Slice(right, func(i, j int) bool { return right[i] < right[j] })
	if len(left) != len(right) {
		return false
	}
	for idx := range left {
		if left[idx] != right[idx] {
			return false
		}
	}
	return true
}

func parseQuestionResponseOptionsValues(values []string) []string {
	out := make([]string, 0, len(values))
	for _, raw := range values {
		option := strings.TrimSpace(raw)
		if option == "" {
			continue
		}
		out = append(out, option)
	}
	return out
}

func normalizeQuestionResponsePayload(rawType string, rawOptions []string) (string, []string) {
	responseType := strings.ToLower(strings.TrimSpace(rawType))
	switch responseType {
	case "yes_no":
		return "multiple_choice", []string{"Yes", "No"}
	case "true_false":
		return "multiple_choice", []string{"True", "False"}
	case "multiple_choice":
		return responseType, parseQuestionResponseOptionsValues(rawOptions)
	case "number":
		return responseType, []string{}
	default:
		return "text", []string{}
	}
}

func interviewQuestionStarterCatalogViews() []interviewQuestionStarterView {
	views := make([]interviewQuestionStarterView, 0, len(interviewQuestionStarterCatalog))
	for _, starter := range interviewQuestionStarterCatalog {
		views = append(views, interviewQuestionStarterView{
			Key:           starter.Key,
			Question:      starter.Question,
			ResponseLabel: interviewQuestionResponseTypeLabel(starter.ResponseType),
		})
	}
	return views
}

func interviewQuestionStarterCatalogByKey() map[string]interviewQuestionStarter {
	byKey := make(map[string]interviewQuestionStarter, len(interviewQuestionStarterCatalog))
	for _, starter := range interviewQuestionStarterCatalog {
		key := strings.TrimSpace(starter.Key)
		if key == "" {
			continue
		}
		byKey[key] = starter
	}
	return byKey
}

func interviewQuestionResponseTypeLabel(responseType string) string {
	switch strings.ToLower(strings.TrimSpace(responseType)) {
	case "yes_no":
		return "Yes / No"
	case "true_false":
		return "True / False"
	case "multiple_choice":
		return "Multiple Choice"
	case "number":
		return "Number"
	default:
		return "Text"
	}
}

func uniqueTrimmedValues(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, raw := range values {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	return out
}

func normalizeStarterQuestionMatch(value string) string {
	return strings.ToLower(strings.Join(strings.Fields(strings.TrimSpace(value)), " "))
}

func parseLocationCandidateInterviewCreatePath(path string) (string, int64, bool) {
	trimmed := strings.TrimPrefix(path, "/admin/locations/")
	trimmed = strings.Trim(trimmed, "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) != 4 || parts[1] != "candidates" || parts[3] != "interviews" {
		return "", 0, false
	}
	locationNumber, err := url.PathUnescape(parts[0])
	if err != nil || strings.TrimSpace(locationNumber) == "" {
		return "", 0, false
	}
	candidateID, err := strconv.ParseInt(strings.TrimSpace(parts[2]), 10, 64)
	if err != nil || candidateID <= 0 {
		return "", 0, false
	}
	return locationNumber, candidateID, true
}

func parseLocationCandidateInterviewLinkCreatePath(path string) (string, int64, bool) {
	trimmed := strings.TrimPrefix(path, "/admin/locations/")
	trimmed = strings.Trim(trimmed, "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) != 4 || parts[1] != "candidates" || parts[3] != "interview-link" {
		return "", 0, false
	}
	locationNumber, err := url.PathUnescape(parts[0])
	if err != nil || strings.TrimSpace(locationNumber) == "" {
		return "", 0, false
	}
	candidateID, err := strconv.ParseInt(strings.TrimSpace(parts[2]), 10, 64)
	if err != nil || candidateID <= 0 {
		return "", 0, false
	}
	return locationNumber, candidateID, true
}

func parseLocationCandidateInterviewLinksCreatePath(path string) (string, int64, bool) {
	trimmed := strings.TrimPrefix(path, "/admin/locations/")
	trimmed = strings.Trim(trimmed, "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) != 4 || parts[1] != "candidates" || parts[3] != "interview-links" {
		return "", 0, false
	}
	locationNumber, err := url.PathUnescape(parts[0])
	if err != nil || strings.TrimSpace(locationNumber) == "" {
		return "", 0, false
	}
	candidateID, err := strconv.ParseInt(strings.TrimSpace(parts[2]), 10, 64)
	if err != nil || candidateID <= 0 {
		return "", 0, false
	}
	return locationNumber, candidateID, true
}

func parseLocationCandidateDecisionPath(path string) (string, int64, bool) {
	trimmed := strings.TrimPrefix(path, "/admin/locations/")
	trimmed = strings.Trim(trimmed, "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) != 4 || parts[1] != "candidates" || parts[3] != "decision" {
		return "", 0, false
	}
	locationNumber, err := url.PathUnescape(parts[0])
	if err != nil || strings.TrimSpace(locationNumber) == "" {
		return "", 0, false
	}
	candidateID, err := strconv.ParseInt(strings.TrimSpace(parts[2]), 10, 64)
	if err != nil || candidateID <= 0 {
		return "", 0, false
	}
	return locationNumber, candidateID, true
}

func parseLocationCandidateDeletePath(path string) (string, int64, bool) {
	trimmed := strings.TrimPrefix(path, "/admin/locations/")
	trimmed = strings.Trim(trimmed, "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) != 4 || parts[1] != "candidates" || parts[3] != "delete" {
		return "", 0, false
	}
	locationNumber, err := url.PathUnescape(parts[0])
	if err != nil || strings.TrimSpace(locationNumber) == "" {
		return "", 0, false
	}
	candidateID, err := strconv.ParseInt(strings.TrimSpace(parts[2]), 10, 64)
	if err != nil || candidateID <= 0 {
		return "", 0, false
	}
	return locationNumber, candidateID, true
}

func parseLocationCandidateScorecardPath(path string) (string, int64, bool) {
	trimmed := strings.TrimPrefix(path, "/admin/locations/")
	trimmed = strings.Trim(trimmed, "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) != 4 || parts[1] != "candidates" || parts[3] != "scorecard" {
		return "", 0, false
	}
	locationNumber, err := url.PathUnescape(parts[0])
	if err != nil || strings.TrimSpace(locationNumber) == "" {
		return "", 0, false
	}
	candidateID, err := strconv.ParseInt(strings.TrimSpace(parts[2]), 10, 64)
	if err != nil || candidateID <= 0 {
		return "", 0, false
	}
	return locationNumber, candidateID, true
}

func parseLocationCandidateDetailPath(path string) (string, int64, bool) {
	trimmed := strings.TrimPrefix(path, "/admin/locations/")
	trimmed = strings.Trim(trimmed, "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) != 3 || parts[1] != "candidates" {
		return "", 0, false
	}
	locationNumber, err := url.PathUnescape(parts[0])
	if err != nil || strings.TrimSpace(locationNumber) == "" {
		return "", 0, false
	}
	candidateID, err := strconv.ParseInt(strings.TrimSpace(parts[2]), 10, 64)
	if err != nil || candidateID <= 0 {
		return "", 0, false
	}
	return locationNumber, candidateID, true
}

func parseLocationCandidateInterviewDetailPath(path string) (string, int64, int64, bool) {
	trimmed := strings.TrimPrefix(path, "/admin/locations/")
	trimmed = strings.Trim(trimmed, "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) != 5 || parts[1] != "candidates" || parts[3] != "interviews" {
		return "", 0, 0, false
	}
	locationNumber, err := url.PathUnescape(parts[0])
	if err != nil || strings.TrimSpace(locationNumber) == "" {
		return "", 0, 0, false
	}
	candidateID, err := strconv.ParseInt(strings.TrimSpace(parts[2]), 10, 64)
	if err != nil || candidateID <= 0 {
		return "", 0, 0, false
	}
	interviewID, err := strconv.ParseInt(strings.TrimSpace(parts[4]), 10, 64)
	if err != nil || interviewID <= 0 {
		return "", 0, 0, false
	}
	return locationNumber, candidateID, interviewID, true
}

func parseLocationCandidateInterviewLinkDetailPath(path string) (string, int64, string, bool) {
	trimmed := strings.TrimPrefix(path, "/admin/locations/")
	trimmed = strings.Trim(trimmed, "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) != 5 || parts[1] != "candidates" || parts[3] != "interview-links" {
		return "", 0, "", false
	}
	locationNumber, err := url.PathUnescape(parts[0])
	if err != nil || strings.TrimSpace(locationNumber) == "" {
		return "", 0, "", false
	}
	candidateID, err := strconv.ParseInt(strings.TrimSpace(parts[2]), 10, 64)
	if err != nil || candidateID <= 0 {
		return "", 0, "", false
	}
	token, err := url.PathUnescape(parts[4])
	if err != nil || strings.TrimSpace(token) == "" {
		return "", 0, "", false
	}
	return locationNumber, candidateID, strings.TrimSpace(token), true
}

func parseLocationCandidateInterviewLinkDeletePath(path string) (string, int64, string, bool) {
	trimmed := strings.TrimPrefix(path, "/admin/locations/")
	trimmed = strings.Trim(trimmed, "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) != 6 || parts[1] != "candidates" || parts[3] != "interview-links" || parts[5] != "delete" {
		return "", 0, "", false
	}
	locationNumber, err := url.PathUnescape(parts[0])
	if err != nil || strings.TrimSpace(locationNumber) == "" {
		return "", 0, "", false
	}
	candidateID, err := strconv.ParseInt(strings.TrimSpace(parts[2]), 10, 64)
	if err != nil || candidateID <= 0 {
		return "", 0, "", false
	}
	token, err := url.PathUnescape(parts[4])
	if err != nil || strings.TrimSpace(token) == "" {
		return "", 0, "", false
	}
	return locationNumber, candidateID, strings.TrimSpace(token), true
}

func parseLocationTimePunchPath(path string) (string, bool) {
	trimmed := strings.TrimPrefix(path, "/admin/locations/")
	trimmed = strings.Trim(trimmed, "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) != 2 || parts[1] != "time-punch" {
		return "", false
	}
	locationNumber, err := url.PathUnescape(parts[0])
	if err != nil || strings.TrimSpace(locationNumber) == "" {
		return "", false
	}
	return locationNumber, true
}

func parseLocationSettingsPath(path string) (string, bool) {
	trimmed := strings.TrimPrefix(path, "/admin/locations/")
	trimmed = strings.Trim(trimmed, "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) != 2 || parts[1] != "settings" {
		return "", false
	}
	locationNumber, err := url.PathUnescape(parts[0])
	if err != nil || strings.TrimSpace(locationNumber) == "" {
		return "", false
	}
	return locationNumber, true
}

func parseLocationSettingsLoginAsLocationPath(path string) (string, bool) {
	trimmed := strings.TrimPrefix(path, "/admin/locations/")
	trimmed = strings.Trim(trimmed, "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) != 3 || parts[1] != "settings" || parts[2] != "login-as-location" {
		return "", false
	}
	locationNumber, err := url.PathUnescape(parts[0])
	if err != nil || strings.TrimSpace(locationNumber) == "" {
		return "", false
	}
	return locationNumber, true
}

func parseLocationTimeOffPath(path string) (string, bool) {
	trimmed := strings.TrimPrefix(path, "/admin/locations/")
	trimmed = strings.Trim(trimmed, "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) != 2 || parts[1] != "time-off" {
		return "", false
	}
	locationNumber, err := url.PathUnescape(parts[0])
	if err != nil || strings.TrimSpace(locationNumber) == "" {
		return "", false
	}
	return locationNumber, true
}

func parseLocationUniformsPath(path string) (string, bool) {
	trimmed := strings.TrimPrefix(path, "/admin/locations/")
	trimmed = strings.Trim(trimmed, "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) != 2 || parts[1] != "uniforms" {
		return "", false
	}
	locationNumber, err := url.PathUnescape(parts[0])
	if err != nil || strings.TrimSpace(locationNumber) == "" {
		return "", false
	}
	return locationNumber, true
}

func parseLocationUniformOrdersArchivedPath(path string) (string, bool) {
	trimmed := strings.TrimPrefix(path, "/admin/locations/")
	trimmed = strings.Trim(trimmed, "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) != 3 || parts[1] != "uniform-orders" || parts[2] != "archived" {
		return "", false
	}
	locationNumber, err := url.PathUnescape(parts[0])
	if err != nil || strings.TrimSpace(locationNumber) == "" {
		return "", false
	}
	return locationNumber, true
}

func parseLocationUniformItemsCreatePath(path string) (string, bool) {
	trimmed := strings.TrimPrefix(path, "/admin/locations/")
	trimmed = strings.Trim(trimmed, "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) != 2 || parts[1] != "uniform-items" {
		return "", false
	}
	locationNumber, err := url.PathUnescape(parts[0])
	if err != nil || strings.TrimSpace(locationNumber) == "" {
		return "", false
	}
	return locationNumber, true
}

func parseLocationUniformItemUpdatePostPath(path string) (string, int64, bool) {
	trimmed := strings.TrimPrefix(path, "/admin/locations/")
	trimmed = strings.Trim(trimmed, "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) != 4 || parts[1] != "uniform-items" || parts[3] != "update" {
		return "", 0, false
	}
	locationNumber, err := url.PathUnescape(parts[0])
	if err != nil || strings.TrimSpace(locationNumber) == "" {
		return "", 0, false
	}
	itemID, err := strconv.ParseInt(strings.TrimSpace(parts[2]), 10, 64)
	if err != nil || itemID <= 0 {
		return "", 0, false
	}
	return locationNumber, itemID, true
}

func parseLocationUniformItemDeletePostPath(path string) (string, int64, bool) {
	trimmed := strings.TrimPrefix(path, "/admin/locations/")
	trimmed = strings.Trim(trimmed, "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) != 4 || parts[1] != "uniform-items" || parts[3] != "delete" {
		return "", 0, false
	}
	locationNumber, err := url.PathUnescape(parts[0])
	if err != nil || strings.TrimSpace(locationNumber) == "" {
		return "", 0, false
	}
	itemID, err := strconv.ParseInt(strings.TrimSpace(parts[2]), 10, 64)
	if err != nil || itemID <= 0 {
		return "", 0, false
	}
	return locationNumber, itemID, true
}

func parseLocationUniformOrderArchivePostPath(path string) (string, int64, bool) {
	trimmed := strings.TrimPrefix(path, "/admin/locations/")
	trimmed = strings.Trim(trimmed, "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) != 4 || parts[1] != "uniform-orders" || parts[3] != "archive" {
		return "", 0, false
	}
	locationNumber, err := url.PathUnescape(parts[0])
	if err != nil || strings.TrimSpace(locationNumber) == "" {
		return "", 0, false
	}
	orderID, err := strconv.ParseInt(strings.TrimSpace(parts[2]), 10, 64)
	if err != nil || orderID <= 0 {
		return "", 0, false
	}
	return locationNumber, orderID, true
}

func parseLocationTimeOffArchivePostPath(path string) (string, int64, bool) {
	trimmed := strings.TrimPrefix(path, "/admin/locations/")
	trimmed = strings.Trim(trimmed, "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) != 4 || parts[1] != "time-off" || parts[3] != "archive" {
		return "", 0, false
	}
	locationNumber, err := url.PathUnescape(parts[0])
	if err != nil || strings.TrimSpace(locationNumber) == "" {
		return "", 0, false
	}
	requestID, err := strconv.ParseInt(strings.TrimSpace(parts[2]), 10, 64)
	if err != nil || requestID <= 0 {
		return "", 0, false
	}
	return locationNumber, requestID, true
}

func parseLocationTimeOffCreatePath(path string) (string, bool) {
	trimmed := strings.TrimPrefix(path, "/admin/locations/")
	trimmed = strings.Trim(trimmed, "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) != 3 || parts[1] != "time-off" || parts[2] != "create" {
		return "", false
	}
	locationNumber, err := url.PathUnescape(parts[0])
	if err != nil || strings.TrimSpace(locationNumber) == "" {
		return "", false
	}
	return locationNumber, true
}

func parseLocationDepartmentsPath(path string) (string, bool) {
	trimmed := strings.TrimPrefix(path, "/admin/locations/")
	trimmed = strings.Trim(trimmed, "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) != 2 || parts[1] != "departments" {
		return "", false
	}
	locationNumber, err := url.PathUnescape(parts[0])
	if err != nil || strings.TrimSpace(locationNumber) == "" {
		return "", false
	}
	return locationNumber, true
}

func parseLocationDepartmentCreatePath(path string) (string, bool) {
	trimmed := strings.TrimPrefix(path, "/admin/locations/")
	trimmed = strings.Trim(trimmed, "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) != 3 || parts[1] != "departments" || parts[2] != "create" {
		return "", false
	}
	locationNumber, err := url.PathUnescape(parts[0])
	if err != nil || strings.TrimSpace(locationNumber) == "" {
		return "", false
	}
	return locationNumber, true
}

func parseLocationJobCreatePath(path string) (string, bool) {
	trimmed := strings.TrimPrefix(path, "/admin/locations/")
	trimmed = strings.Trim(trimmed, "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) != 3 || parts[1] != "jobs" || parts[2] != "create" {
		return "", false
	}
	locationNumber, err := url.PathUnescape(parts[0])
	if err != nil || strings.TrimSpace(locationNumber) == "" {
		return "", false
	}
	return locationNumber, true
}

func parseLocationJobUpdatePath(path string) (string, int64, bool) {
	trimmed := strings.TrimPrefix(path, "/admin/locations/")
	trimmed = strings.Trim(trimmed, "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) != 4 || parts[1] != "jobs" || parts[3] != "update" {
		return "", 0, false
	}
	locationNumber, err := url.PathUnescape(parts[0])
	if err != nil || strings.TrimSpace(locationNumber) == "" {
		return "", 0, false
	}
	jobID, err := strconv.ParseInt(strings.TrimSpace(parts[2]), 10, 64)
	if err != nil || jobID <= 0 {
		return "", 0, false
	}
	return locationNumber, jobID, true
}

func parseLocationJobAssignDepartmentsPath(path string) (string, int64, bool) {
	trimmed := strings.TrimPrefix(path, "/admin/locations/")
	trimmed = strings.Trim(trimmed, "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) != 5 || parts[1] != "jobs" || parts[3] != "departments" || parts[4] != "assign" {
		return "", 0, false
	}
	locationNumber, err := url.PathUnescape(parts[0])
	if err != nil || strings.TrimSpace(locationNumber) == "" {
		return "", 0, false
	}
	jobID, err := strconv.ParseInt(strings.TrimSpace(parts[2]), 10, 64)
	if err != nil || jobID <= 0 {
		return "", 0, false
	}
	return locationNumber, jobID, true
}

func parseLocationUniformOrderCreatePath(path string) (string, bool) {
	trimmed := strings.TrimPrefix(path, "/admin/locations/")
	trimmed = strings.Trim(trimmed, "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) != 3 || parts[1] != "uniform-orders" || parts[2] != "create" {
		return "", false
	}
	locationNumber, err := url.PathUnescape(parts[0])
	if err != nil || strings.TrimSpace(locationNumber) == "" {
		return "", false
	}
	return locationNumber, true
}

func parseLocationUniformOrderLineSettlementPostPath(path string) (string, int64, int64, bool) {
	trimmed := strings.TrimPrefix(path, "/admin/locations/")
	trimmed = strings.Trim(trimmed, "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) != 6 || parts[1] != "uniform-orders" || parts[3] != "lines" || parts[5] != "settlement" {
		return "", 0, 0, false
	}
	locationNumber, err := url.PathUnescape(parts[0])
	if err != nil || strings.TrimSpace(locationNumber) == "" {
		return "", 0, 0, false
	}
	orderID, err := strconv.ParseInt(strings.TrimSpace(parts[2]), 10, 64)
	if err != nil || orderID <= 0 {
		return "", 0, 0, false
	}
	lineID, err := strconv.ParseInt(strings.TrimSpace(parts[4]), 10, 64)
	if err != nil || lineID <= 0 {
		return "", 0, 0, false
	}
	return locationNumber, orderID, lineID, true
}

func parseLocationUniformOrderDeletePostPath(path string) (string, int64, bool) {
	trimmed := strings.TrimPrefix(path, "/admin/locations/")
	trimmed = strings.Trim(trimmed, "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) != 4 || parts[1] != "uniform-orders" || parts[3] != "delete" {
		return "", 0, false
	}
	locationNumber, err := url.PathUnescape(parts[0])
	if err != nil || strings.TrimSpace(locationNumber) == "" {
		return "", 0, false
	}
	orderID, err := strconv.ParseInt(strings.TrimSpace(parts[2]), 10, 64)
	if err != nil || orderID <= 0 {
		return "", 0, false
	}
	return locationNumber, orderID, true
}

func parseLocationUniformImageMovePostPath(path string) (string, int64, int64, bool) {
	trimmed := strings.TrimPrefix(path, "/admin/locations/")
	trimmed = strings.Trim(trimmed, "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) != 6 || parts[1] != "uniform-items" || parts[3] != "images" || parts[5] != "move" {
		return "", 0, 0, false
	}
	locationNumber, err := url.PathUnescape(parts[0])
	if err != nil || strings.TrimSpace(locationNumber) == "" {
		return "", 0, 0, false
	}
	itemID, err := strconv.ParseInt(strings.TrimSpace(parts[2]), 10, 64)
	if err != nil || itemID <= 0 {
		return "", 0, 0, false
	}
	imageID, err := strconv.ParseInt(strings.TrimSpace(parts[4]), 10, 64)
	if err != nil || imageID <= 0 {
		return "", 0, 0, false
	}
	return locationNumber, itemID, imageID, true
}

func parseLocationUniformItemPath(path string) (string, int64, bool) {
	trimmed := strings.TrimPrefix(path, "/admin/locations/")
	trimmed = strings.Trim(trimmed, "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) != 3 || parts[1] != "uniform-items" {
		return "", 0, false
	}
	locationNumber, err := url.PathUnescape(parts[0])
	if err != nil || strings.TrimSpace(locationNumber) == "" {
		return "", 0, false
	}
	itemID, err := strconv.ParseInt(strings.TrimSpace(parts[2]), 10, 64)
	if err != nil || itemID <= 0 {
		return "", 0, false
	}
	return locationNumber, itemID, true
}

func parseLocationUniformItemImagesAddPostPath(path string) (string, int64, bool) {
	trimmed := strings.TrimPrefix(path, "/admin/locations/")
	trimmed = strings.Trim(trimmed, "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) != 4 || parts[1] != "uniform-items" || parts[3] != "images" {
		return "", 0, false
	}
	locationNumber, err := url.PathUnescape(parts[0])
	if err != nil || strings.TrimSpace(locationNumber) == "" {
		return "", 0, false
	}
	itemID, err := strconv.ParseInt(strings.TrimSpace(parts[2]), 10, 64)
	if err != nil || itemID <= 0 {
		return "", 0, false
	}
	return locationNumber, itemID, true
}

func parseLocationUniformItemImageDeletePostPath(path string) (string, int64, int64, bool) {
	trimmed := strings.TrimPrefix(path, "/admin/locations/")
	trimmed = strings.Trim(trimmed, "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) != 6 || parts[1] != "uniform-items" || parts[3] != "images" || parts[5] != "delete" {
		return "", 0, 0, false
	}
	locationNumber, err := url.PathUnescape(parts[0])
	if err != nil || strings.TrimSpace(locationNumber) == "" {
		return "", 0, 0, false
	}
	itemID, err := strconv.ParseInt(strings.TrimSpace(parts[2]), 10, 64)
	if err != nil || itemID <= 0 {
		return "", 0, 0, false
	}
	imageID, err := strconv.ParseInt(strings.TrimSpace(parts[4]), 10, 64)
	if err != nil || imageID <= 0 {
		return "", 0, 0, false
	}
	return locationNumber, itemID, imageID, true
}

func parseLocationBusinessDaysPath(path string) (string, bool) {
	trimmed := strings.TrimPrefix(path, "/admin/locations/")
	trimmed = strings.Trim(trimmed, "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) != 2 || parts[1] != "business-days" {
		return "", false
	}
	locationNumber, err := url.PathUnescape(parts[0])
	if err != nil || strings.TrimSpace(locationNumber) == "" {
		return "", false
	}
	return locationNumber, true
}

func parseLocationBusinessDayOpenPath(path string) (string, bool) {
	trimmed := strings.TrimPrefix(path, "/admin/locations/")
	trimmed = strings.Trim(trimmed, "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) != 3 || parts[1] != "business-days" || parts[2] != "open" {
		return "", false
	}
	locationNumber, err := url.PathUnescape(parts[0])
	if err != nil || strings.TrimSpace(locationNumber) == "" {
		return "", false
	}
	return locationNumber, true
}

func parseLocationBusinessDayDetailPath(path string) (string, string, bool) {
	trimmed := strings.TrimPrefix(path, "/admin/locations/")
	trimmed = strings.Trim(trimmed, "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) != 3 || parts[1] != "business-days" {
		return "", "", false
	}
	locationNumber, err := url.PathUnescape(parts[0])
	if err != nil || strings.TrimSpace(locationNumber) == "" {
		return "", "", false
	}
	businessDate, err := url.PathUnescape(parts[2])
	if err != nil || strings.TrimSpace(businessDate) == "" {
		return "", "", false
	}
	return locationNumber, strings.TrimSpace(businessDate), true
}

func parseLocationTimePunchDeletePath(path string) (string, int64, bool) {
	trimmed := strings.TrimPrefix(path, "/admin/locations/")
	trimmed = strings.Trim(trimmed, "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) != 4 || parts[1] != "time-punch" || parts[3] != "delete" {
		return "", 0, false
	}
	locationNumber, err := url.PathUnescape(parts[0])
	if err != nil || strings.TrimSpace(locationNumber) == "" {
		return "", 0, false
	}
	entryID, err := strconv.ParseInt(strings.TrimSpace(parts[2]), 10, 64)
	if err != nil || entryID <= 0 {
		return "", 0, false
	}
	return locationNumber, entryID, true
}

func parseLocationTimePunchArchivePostPath(path string) (string, int64, bool) {
	trimmed := strings.TrimPrefix(path, "/admin/locations/")
	trimmed = strings.Trim(trimmed, "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) != 4 || parts[1] != "time-punch" || parts[3] != "archive" {
		return "", 0, false
	}
	locationNumber, err := url.PathUnescape(parts[0])
	if err != nil || strings.TrimSpace(locationNumber) == "" {
		return "", 0, false
	}
	entryID, err := strconv.ParseInt(strings.TrimSpace(parts[2]), 10, 64)
	if err != nil || entryID <= 0 {
		return "", 0, false
	}
	return locationNumber, entryID, true
}

func parseLocationTimePunchCreatePath(path string) (string, bool) {
	trimmed := strings.TrimPrefix(path, "/admin/locations/")
	trimmed = strings.Trim(trimmed, "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) != 3 || parts[1] != "time-punch" || parts[2] != "create" {
		return "", false
	}
	locationNumber, err := url.PathUnescape(parts[0])
	if err != nil || strings.TrimSpace(locationNumber) == "" {
		return "", false
	}
	return locationNumber, true
}

func parseLocationEmployeeActionPath(path, action string) (string, string, bool) {
	trimmed := strings.TrimPrefix(path, "/admin/locations/")
	trimmed = strings.Trim(trimmed, "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) != 4 || parts[1] != "employees" || parts[3] != action {
		return "", "", false
	}
	locationNumber, err := url.PathUnescape(parts[0])
	if err != nil || strings.TrimSpace(locationNumber) == "" {
		return "", "", false
	}
	timePunchName, err := url.PathUnescape(parts[2])
	if err != nil || strings.TrimSpace(timePunchName) == "" {
		return "", "", false
	}
	return locationNumber, timePunchName, true
}

func employeePaperworkLink(r *http.Request, locationNumber, timePunchName string) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host + "/employee/paperwork/" + url.PathEscape(locationNumber) + "/" + url.PathEscape(timePunchName)
}

func encodePathTail(pathTail string) string {
	parts := strings.Split(strings.Trim(pathTail, "/"), "/")
	encoded := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		encoded = append(encoded, url.PathEscape(part))
	}
	return strings.Join(encoded, "/")
}

func formatPayAmountInput(cents int64) string {
	if cents <= 0 {
		return ""
	}
	return fmt.Sprintf("%.2f", float64(cents)/100.0)
}

func splitBirthdayInput(raw string) (string, string, string) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", "", ""
	}
	layouts := []string{
		"01/02/2006",
		"1/2/2006",
		"2006-01-02",
		"01-02-2006",
		"1-2-2006",
		"2006/01/02",
	}
	for _, layout := range layouts {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed.Format("01"), parsed.Format("02"), parsed.Format("2006")
		}
	}
	replacer := strings.NewReplacer("-", "/", ".", "/", " ", "/")
	parts := strings.Split(replacer.Replace(value), "/")
	if len(parts) == 3 {
		a := strings.TrimSpace(parts[0])
		b := strings.TrimSpace(parts[1])
		c := strings.TrimSpace(parts[2])
		if len(a) == 4 {
			return padTwo(b), padTwo(c), a
		}
		return padTwo(a), padTwo(b), c
	}
	return "", "", ""
}

func manualPaperworkRequiredFieldsForUpload(emp *employeeView) []string {
	if emp == nil {
		return []string{"Employee record"}
	}
	missing := make([]string, 0, 14)
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
	if _, _, year := splitBirthdayInput(emp.Birthday); strings.TrimSpace(year) == "" {
		missing = append(missing, "Birthday")
	}
	require(emp.Email, "Email")
	require(emp.Phone, "Phone")
	require(emp.Address, "Address")
	require(emp.City, "City")
	require(emp.State, "State")
	require(emp.ZipCode, "Zip Code")
	if emp.HasCompletedPaperwork && !emp.HasClockInPIN {
		missing = append(missing, "Clock In PIN")
	}
	return missing
}

func employeesWithMissingRequiredProfileFields(employees []employeeView) []employeeProfileCompletenessView {
	out := make([]employeeProfileCompletenessView, 0, len(employees))
	for i := range employees {
		missing := manualPaperworkRequiredFieldsForUpload(&employees[i])
		if len(missing) == 0 {
			continue
		}
		out = append(out, employeeProfileCompletenessView{
			Employee:      employees[i],
			MissingFields: missing,
		})
	}
	return out
}

func padTwo(v string) string {
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || n < 0 {
		return strings.TrimSpace(v)
	}
	return fmt.Sprintf("%02d", n)
}

func parseLocationEmployeeI9UploadPath(path string) (string, string, bool) {
	return parseLocationEmployeeActionPath(path, "i9")
}

func parseLocationEmployeeDetailsUpdatePath(path string) (string, string, bool) {
	trimmed := strings.TrimPrefix(path, "/admin/locations/")
	trimmed = strings.Trim(trimmed, "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) != 5 || parts[1] != "employees" || parts[3] != "details" || parts[4] != "update" {
		return "", "", false
	}
	locationNumber, err := url.PathUnescape(parts[0])
	if err != nil || strings.TrimSpace(locationNumber) == "" {
		return "", "", false
	}
	timePunchName, err := url.PathUnescape(parts[2])
	if err != nil || strings.TrimSpace(timePunchName) == "" {
		return "", "", false
	}
	return locationNumber, timePunchName, true
}

func parseLocationEmployeeW4UploadPath(path string) (string, string, bool) {
	return parseLocationEmployeeActionPath(path, "w4")
}

func parseLocationEmployeeLoginAsTeamPath(path string) (string, string, bool) {
	return parseLocationEmployeeActionPath(path, "login-as-team")
}

func parseLocationEmployeeTerminatePath(path string) (string, string, bool) {
	return parseLocationEmployeeActionPath(path, "terminate")
}

func parseLocationEmployeeI9DocumentUploadPath(path string) (string, string, bool) {
	trimmed := strings.TrimPrefix(path, "/admin/locations/")
	trimmed = strings.Trim(trimmed, "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) != 5 || parts[1] != "employees" || parts[3] != "i9" || parts[4] != "documents" {
		return "", "", false
	}
	locationNumber, err := url.PathUnescape(parts[0])
	if err != nil || strings.TrimSpace(locationNumber) == "" {
		return "", "", false
	}
	timePunchName, err := url.PathUnescape(parts[2])
	if err != nil || strings.TrimSpace(timePunchName) == "" {
		return "", "", false
	}
	return locationNumber, timePunchName, true
}

func parseLocationEmployeeI9DocumentDeletePath(path string) (string, string, int64, bool) {
	trimmed := strings.TrimPrefix(path, "/admin/locations/")
	trimmed = strings.Trim(trimmed, "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) != 7 || parts[1] != "employees" || parts[3] != "i9" || parts[4] != "documents" || parts[6] != "delete" {
		return "", "", 0, false
	}
	locationNumber, err := url.PathUnescape(parts[0])
	if err != nil || strings.TrimSpace(locationNumber) == "" {
		return "", "", 0, false
	}
	timePunchName, err := url.PathUnescape(parts[2])
	if err != nil || strings.TrimSpace(timePunchName) == "" {
		return "", "", 0, false
	}
	docID, err := strconv.ParseInt(strings.TrimSpace(parts[5]), 10, 64)
	if err != nil || docID <= 0 {
		return "", "", 0, false
	}
	return locationNumber, timePunchName, docID, true
}

func mapEmployeeI9FilePathToAPI(path string) (string, bool) {
	if locationNumber, timePunchName, ok := parseLocationEmployeeActionPath(strings.TrimSuffix(path, "/file"), "i9"); ok {
		return "/api/admin/locations/" + url.PathEscape(locationNumber) + "/employees/" + url.PathEscape(timePunchName) + "/i9/file", true
	}
	trimmed := strings.TrimPrefix(path, "/admin/locations/")
	trimmed = strings.Trim(trimmed, "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) == 6 && parts[1] == "employees" && parts[2] == "archived" && parts[4] == "i9" && parts[5] == "file" {
		locationNumber, err := url.PathUnescape(parts[0])
		if err != nil || strings.TrimSpace(locationNumber) == "" {
			return "", false
		}
		timePunchName, err := url.PathUnescape(parts[3])
		if err != nil || strings.TrimSpace(timePunchName) == "" {
			return "", false
		}
		return "/api/admin/locations/" + url.PathEscape(locationNumber) + "/employees/archived/" + url.PathEscape(timePunchName) + "/i9/file", true
	}
	return "", false
}

func mapEmployeeI9DocumentFilePathToAPI(path string) (string, bool) {
	trimmed := strings.TrimPrefix(path, "/admin/locations/")
	trimmed = strings.Trim(trimmed, "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) == 6 && parts[1] == "employees" && parts[3] == "i9" && parts[4] == "documents" {
		locationNumber, err := url.PathUnescape(parts[0])
		if err != nil || strings.TrimSpace(locationNumber) == "" {
			return "", false
		}
		timePunchName, err := url.PathUnescape(parts[2])
		if err != nil || strings.TrimSpace(timePunchName) == "" {
			return "", false
		}
		docID, err := strconv.ParseInt(strings.TrimSpace(parts[5]), 10, 64)
		if err != nil || docID <= 0 {
			return "", false
		}
		return "/api/admin/locations/" + url.PathEscape(locationNumber) + "/employees/" + url.PathEscape(timePunchName) + "/i9/documents/" + strconv.FormatInt(docID, 10), true
	}
	if len(parts) == 7 && parts[1] == "employees" && parts[2] == "archived" && parts[4] == "i9" && parts[5] == "documents" {
		locationNumber, err := url.PathUnescape(parts[0])
		if err != nil || strings.TrimSpace(locationNumber) == "" {
			return "", false
		}
		timePunchName, err := url.PathUnescape(parts[3])
		if err != nil || strings.TrimSpace(timePunchName) == "" {
			return "", false
		}
		docID, err := strconv.ParseInt(strings.TrimSpace(parts[6]), 10, 64)
		if err != nil || docID <= 0 {
			return "", false
		}
		return "/api/admin/locations/" + url.PathEscape(locationNumber) + "/employees/archived/" + url.PathEscape(timePunchName) + "/i9/documents/" + strconv.FormatInt(docID, 10), true
	}
	return "", false
}

func mapEmployeeW4FilePathToAPI(path string) (string, bool) {
	if locationNumber, timePunchName, ok := parseLocationEmployeeActionPath(strings.TrimSuffix(path, "/file"), "w4"); ok {
		return "/api/admin/locations/" + url.PathEscape(locationNumber) + "/employees/" + url.PathEscape(timePunchName) + "/w4/file", true
	}
	trimmed := strings.TrimPrefix(path, "/admin/locations/")
	trimmed = strings.Trim(trimmed, "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) == 6 && parts[1] == "employees" && parts[2] == "archived" && parts[4] == "w4" && parts[5] == "file" {
		locationNumber, err := url.PathUnescape(parts[0])
		if err != nil || strings.TrimSpace(locationNumber) == "" {
			return "", false
		}
		timePunchName, err := url.PathUnescape(parts[3])
		if err != nil || strings.TrimSpace(timePunchName) == "" {
			return "", false
		}
		return "/api/admin/locations/" + url.PathEscape(locationNumber) + "/employees/archived/" + url.PathEscape(timePunchName) + "/w4/file", true
	}
	return "", false
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
