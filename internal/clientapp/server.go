package clientapp

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"log"
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
	csrfHeaderName    = "X-CSRF-Token"
	sessionCookieName = "cfasuite_session"
)

type Config struct {
	Addr         string
	APIBaseURL   string
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
}

type pageData struct {
	Error      string
	CSRF       string
	Page       int
	Token      string
	Search     string
	ReturnPath string

	Locations  []locationView
	HasPrev    bool
	HasNext    bool
	PrevPage   int
	NextPage   int
	TotalCount int

	Location                 *locationView
	Employee                 *employeeView
	BusinessDay              *businessDayView
	Employees                []employeeView
	BusinessDays             []businessDayView
	ArchivedEmployees        []employeeView
	TimePunchEntries         []timePunchEntryView
	ArchivedTimePunchEntries []timePunchEntryView
	TimeOffRequests          []timeOffRequestView
	ArchivedTimeOffRequests  []timeOffRequestView
	UniformItems             []uniformItemView
	UniformOrders            []uniformOrderView
	ArchivedOrders           []uniformOrderView
	UniformItem              *uniformItemView
	Candidates               []candidateView
	ArchivedCandidates       []candidateView
	EmployeeScorecards       []candidateView
	CandidateValues          []candidateValueView
	InterviewNames           []candidateInterviewNameView
	InterviewQuestions       []candidateInterviewQuestionView
	InterviewLinks           []candidateInterviewLinkView
	Candidate                *candidateView
	Interview                *candidateInterviewView
	InterviewLink            *candidateInterviewLinkView
	EmployeeNames            []string
	Departments              []string
	SuccessMessage           string
	UploadLink               string
	EmployeePaperworkLink    string
	LocationSettings         *locationSettingsView
	TimePunchLink            string
	TimeOffLink              string
	UniformLink              string
	EmployeeI9               *employeeI9View
	EmployeeI9Documents      []employeeI9DocumentView
	EmployeeW4               *employeeI9View
	PaperworkSections        []paperworkSectionView
	IsArchivedEmployee       bool
}

type locationView struct {
	Name      string `json:"name"`
	Number    string `json:"number"`
	Email     string `json:"email"`
	Phone     string `json:"phone"`
	CreatedAt string `json:"createdAt"`
}

type employeeView struct {
	FirstName     string `json:"firstName"`
	LastName      string `json:"lastName"`
	TimePunchName string `json:"timePunchName"`
	Department    string `json:"department"`
	Birthday      string `json:"birthday"`
	HasPhoto      bool   `json:"hasPhoto"`
	ArchivedAt    string `json:"archivedAt"`
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
}

type paperworkSectionView struct {
	Type         string
	Label        string
	HasDocuments bool
	Form         *employeeI9View
	Documents    []employeeI9DocumentView
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

type timePunchEntryView struct {
	ID            int64  `json:"id"`
	TimePunchName string `json:"timePunchName"`
	PunchDate     string `json:"punchDate"`
	TimeIn        string `json:"timeIn"`
	TimeOut       string `json:"timeOut"`
	Note          string `json:"note"`
	ArchivedAt    string `json:"archivedAt"`
	CreatedAt     string `json:"createdAt"`
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
	ID        int64              `json:"id"`
	Name      string             `json:"name"`
	Price     float64            `json:"price"`
	Enabled   bool               `json:"enabled"`
	ImageData string             `json:"imageData"`
	ImageMime string             `json:"imageMime"`
	Images    []uniformImageView `json:"images"`
	Sizes     []string           `json:"sizes"`
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
	Total         float64                `json:"total"`
	CreatedAt     string                 `json:"createdAt"`
	ArchivedAt    string                 `json:"archivedAt"`
}

type uniformOrderLineView struct {
	ID          int64   `json:"id"`
	OrderID     int64   `json:"orderId"`
	ItemID      int64   `json:"itemId"`
	ItemName    string  `json:"itemName"`
	SizeOption  string  `json:"sizeOption"`
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
	ID               int64    `json:"id"`
	LocationNumber   string   `json:"locationNumber"`
	InterviewNameID  int64    `json:"interviewNameId"`
	InterviewName    string   `json:"interviewName"`
	InterviewNameIDs []int64  `json:"interviewNameIds"`
	InterviewNames   []string `json:"interviewNames"`
	Question         string   `json:"question"`
	CreatedAt        string   `json:"createdAt"`
	UpdatedAt        string   `json:"updatedAt"`
}

type candidateInterviewLinkView struct {
	Token                    string `json:"token"`
	LocationNumber           string `json:"locationNumber"`
	CandidateID              int64  `json:"candidateId"`
	InterviewerTimePunchName string `json:"interviewerTimePunchName"`
	InterviewType            string `json:"interviewType"`
	Link                     string `json:"link"`
	ExpiresAt                string `json:"expiresAt"`
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

//go:embed templates/admin.html templates/login.html templates/location_apps.html templates/location.html templates/location_settings.html templates/archived_employees.html templates/time_punch.html templates/time_off.html templates/business_days.html templates/business_day.html templates/employee.html templates/uniforms.html templates/uniform_orders_archived.html templates/uniform_item.html templates/candidates.html templates/interview_process.html templates/candidate_detail.html templates/candidate_interview.html templates/candidate_interview_link.html templates/candidate_scorecard.html templates/public_photo_upload.html templates/public_employee_paperwork.html templates/public_candidate_interview.html templates/public_time_punch.html templates/public_time_off.html templates/public_uniform_order.html templates/public_uniform_order_item.html assets/app.css
var templatesFS embed.FS

type server struct {
	apiBaseURL                 string
	apiClient                  *http.Client
	adminTmpl                  *template.Template
	loginTmpl                  *template.Template
	locationAppsTmpl           *template.Template
	locationTmpl               *template.Template
	locationSettingsTmpl       *template.Template
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
		locationAppsTmpl:           template.Must(template.ParseFS(templatesFS, "templates/location_apps.html")),
		locationTmpl:               template.Must(template.ParseFS(templatesFS, "templates/location.html")),
		locationSettingsTmpl:       template.Must(template.ParseFS(templatesFS, "templates/location_settings.html")),
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
	mux.Handle("/amin", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/admin", http.StatusFound)
	}))
	mux.Handle("/admin", middleware.Chain(http.HandlerFunc(s.adminPage), s.requireAdmin))
	mux.Handle("/admin/locations", middleware.Chain(http.HandlerFunc(s.createLocationProxy), s.requireAdmin))
	mux.Handle("/admin/locations/", middleware.Chain(http.HandlerFunc(s.locationRoutes), s.requireAdmin))
	mux.Handle("/assets/app.css", http.HandlerFunc(s.appCSSFile))
	mux.Handle("/assets/i9-template.pdf", middleware.Chain(http.HandlerFunc(s.i9TemplateFile), s.requireAdmin))
	mux.Handle("/assets/w4-template.pdf", middleware.Chain(http.HandlerFunc(s.w4TemplateFile), s.requireAdmin))
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
	if s.sessionIsValid(r) {
		http.Redirect(w, r, "/admin", http.StatusFound)
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

	for _, setCookie := range apiResp.Header.Values("Set-Cookie") {
		w.Header().Add("Set-Cookie", setCookie)
	}
	http.Redirect(w, r, "/admin", http.StatusFound)
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
	if err := renderHTMLTemplate(w, s.locationAppsTmpl, pageData{
		Location: location,
	}); err != nil {
		http.Error(w, "template render failed", http.StatusInternalServerError)
		log.Printf("location apps template render failed: %v", err)
	}
}

func (s *server) locationRoutes(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		if locationNumber, ok := parseLocationEmployeeCreatePath(r.URL.Path); ok {
			s.createEmployeeProxy(w, r, locationNumber)
			return
		}
		if locationNumber, timePunchName, ok := parseLocationEmployeeI9UploadPath(r.URL.Path); ok {
			s.uploadEmployeeI9Proxy(w, r, locationNumber, timePunchName)
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
		if locationNumber, requestID, ok := parseLocationTimeOffArchivePostPath(r.URL.Path); ok {
			s.archiveTimeOffRequestProxy(w, r, locationNumber, requestID)
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
	settings, err := s.fetchLocationSettings(r, locationNumber)
	if err != nil {
		http.Error(w, "unable to load location settings", http.StatusBadGateway)
		return
	}

	if err := renderHTMLTemplate(w, s.locationTmpl, pageData{
		Location:       location,
		CSRF:           csrfToken,
		Employees:      employees,
		Departments:    normalizeDepartments(settings.Departments),
		SuccessMessage: r.URL.Query().Get("message"),
		Error:          r.URL.Query().Get("error"),
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
	if err := renderHTMLTemplate(w, s.locationSettingsTmpl, pageData{
		Location:         location,
		CSRF:             csrfToken,
		LocationSettings: settings,
		SuccessMessage:   r.URL.Query().Get("message"),
		Error:            r.URL.Query().Get("error"),
	}); err != nil {
		http.Error(w, "template render failed", http.StatusInternalServerError)
		log.Printf("location settings template render failed: %v", err)
	}
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
	if err := renderHTMLTemplate(w, s.candidatesTmpl, pageData{
		Location:           location,
		CSRF:               csrfToken,
		Candidates:         candidates,
		ArchivedCandidates: archived,
		Search:             archiveSearch,
		SuccessMessage:     r.URL.Query().Get("message"),
		Error:              r.URL.Query().Get("error"),
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
	if err := renderHTMLTemplate(w, s.interviewProcessTmpl, pageData{
		Location:           location,
		CSRF:               csrfToken,
		CandidateValues:    values,
		InterviewNames:     interviewNames,
		InterviewQuestions: interviewQuestions,
		SuccessMessage:     r.URL.Query().Get("message"),
		Error:              r.URL.Query().Get("error"),
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
	interviewLinks, err := s.fetchCandidateInterviewLinks(r, locationNumber, candidateID)
	if err != nil {
		http.Error(w, "unable to load interview links", http.StatusBadGateway)
		return
	}
	if err := renderHTMLTemplate(w, s.candidateDetailTmpl, pageData{
		Location:        location,
		CSRF:            csrfToken,
		Candidate:       candidate,
		CandidateValues: values,
		InterviewNames:  interviewNames,
		InterviewLinks:  interviewLinks,
		Employees:       interviewers,
		SuccessMessage:  r.URL.Query().Get("message"),
		Error:           r.URL.Query().Get("error"),
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
	payload := map[string]any{
		"interviewNameId":  interviewNameID,
		"interviewNameIds": interviewNameIDs,
		"question":         strings.TrimSpace(r.FormValue("question")),
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

func (s *server) updateCandidateValueProxy(w http.ResponseWriter, r *http.Request, locationNumber string, valueID int64) {
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
	payload := map[string]any{
		"interviewNameId":  interviewNameID,
		"interviewNameIds": interviewNameIDs,
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
		"/admin/locations/"+url.PathEscape(locationNumber)+"/candidates/"+strconv.FormatInt(candidateID, 10)+"?error="+url.QueryEscape("Interviews can only be completed through generated links")+"#create-interviews",
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
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/candidates/"+strconv.FormatInt(candidateID, 10)+"?error=Invalid+form+submission#create-interviews", http.StatusFound)
		return
	}
	csrfToken := strings.TrimSpace(r.FormValue("csrf_token"))
	if csrfToken == "" {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/candidates/"+strconv.FormatInt(candidateID, 10)+"?error=Missing+csrf+token#create-interviews", http.StatusFound)
		return
	}
	body, _ := json.Marshal(map[string]string{
		"interviewerTimePunchName": strings.TrimSpace(r.FormValue("interviewer_time_punch_name")),
		"interviewType":            strings.TrimSpace(r.FormValue("interview_type")),
	})
	apiReq, err := http.NewRequestWithContext(
		r.Context(),
		http.MethodPost,
		s.apiBaseURL+"/api/admin/locations/"+url.PathEscape(locationNumber)+"/candidates/"+strconv.FormatInt(candidateID, 10)+"/interview-link",
		bytes.NewReader(body),
	)
	if err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/candidates/"+strconv.FormatInt(candidateID, 10)+"?error=Unable+to+create+interview#create-interviews", http.StatusFound)
		return
	}
	copySessionCookieHeader(r, apiReq)
	apiReq.Header.Set("Content-Type", "application/json")
	apiReq.Header.Set(csrfHeaderName, csrfToken)
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/candidates/"+strconv.FormatInt(candidateID, 10)+"?error=Service+unavailable#create-interviews", http.StatusFound)
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
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/candidates/"+strconv.FormatInt(candidateID, 10)+"?error="+url.QueryEscape(msg)+"#create-interviews", http.StatusFound)
		return
	}
	var payload interviewLinkResponse
	if err := json.Unmarshal(respBody, &payload); err != nil || strings.TrimSpace(payload.Token) == "" {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/candidates/"+strconv.FormatInt(candidateID, 10)+"?error=Unable+to+read+interview+link#create-interviews", http.StatusFound)
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
	payload := map[string]string{"decision": strings.TrimSpace(r.FormValue("decision"))}
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
	switch r.Method {
	case http.MethodGet:
		s.publicEmployeePaperworkPage(w, r, pathTail)
	case http.MethodPost:
		s.publicEmployeePaperworkSubmit(w, r, pathTail)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
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
	switch r.Method {
	case http.MethodGet:
		s.publicTimePunchPage(w, r, token)
	case http.MethodPost:
		s.publicTimePunchSubmit(w, r, token)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *server) publicTimeOffRoutes(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.URL.Path, "/time-off/")
	token = strings.TrimSpace(strings.Trim(token, "/"))
	if token == "" {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodGet:
		s.publicTimeOffPage(w, r, token)
	case http.MethodPost:
		s.publicTimeOffSubmit(w, r, token)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
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
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.publicUniformOrderPage(w, r, token)
		return
	}

	if len(parts) == 3 && parts[1] == "item" {
		itemID, err := strconv.ParseInt(strings.TrimSpace(parts[2]), 10, 64)
		if err != nil || itemID <= 0 {
			http.NotFound(w, r)
			return
		}
		switch r.Method {
		case http.MethodGet:
			s.publicUniformOrderItemPage(w, r, token, itemID)
		case http.MethodPost:
			s.publicUniformOrderItemSubmit(w, r, token, itemID)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
		return
	}

	http.NotFound(w, r)
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
	i9, docs, err := s.fetchEmployeePaperwork(r, locationNumber, timePunchName, false, "i9")
	if err != nil {
		http.Error(w, "unable to load employee i9 records", http.StatusBadGateway)
		return
	}
	w4, _, err := s.fetchEmployeePaperwork(r, locationNumber, timePunchName, false, "w4")
	if err != nil {
		http.Error(w, "unable to load employee w4 records", http.StatusBadGateway)
		return
	}
	settings, err := s.fetchLocationSettings(r, locationNumber)
	if err != nil {
		http.Error(w, "unable to load location settings", http.StatusBadGateway)
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

	if err := renderHTMLTemplate(w, s.employeeTmpl, pageData{
		CSRF:                  csrfToken,
		Location:              location,
		Employee:              employee,
		EmployeePaperworkLink: employeePaperworkLink(r, locationNumber, timePunchName),
		Departments:           normalizeDepartments(settings.Departments),
		EmployeeI9:            i9,
		EmployeeI9Documents:   docs,
		EmployeeW4:            w4,
		EmployeeScorecards:    scorecards,
		PaperworkSections:     paperworkSections,
		IsArchivedEmployee:    false,
		SuccessMessage:        r.URL.Query().Get("message"),
		Error:                 r.URL.Query().Get("error"),
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
	i9, docs, err := s.fetchEmployeePaperwork(r, locationNumber, timePunchName, true, "i9")
	if err != nil {
		http.Error(w, "unable to load archived employee i9 records", http.StatusBadGateway)
		return
	}
	w4, _, err := s.fetchEmployeePaperwork(r, locationNumber, timePunchName, true, "w4")
	if err != nil {
		http.Error(w, "unable to load archived employee w4 records", http.StatusBadGateway)
		return
	}
	settings, err := s.fetchLocationSettings(r, locationNumber)
	if err != nil {
		http.Error(w, "unable to load location settings", http.StatusBadGateway)
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
	if err := renderHTMLTemplate(w, s.employeeTmpl, pageData{
		CSRF:                csrfToken,
		Location:            location,
		Employee:            employee,
		Departments:         normalizeDepartments(settings.Departments),
		EmployeeI9:          i9,
		EmployeeI9Documents: docs,
		EmployeeW4:          w4,
		EmployeeScorecards:  scorecards,
		PaperworkSections:   paperworkSections,
		IsArchivedEmployee:  true,
		SuccessMessage:      r.URL.Query().Get("message"),
		Error:               r.URL.Query().Get("error"),
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
	token, err := s.fetchLocationTimePunchToken(r, locationNumber)
	if err != nil {
		http.Error(w, "unable to load time punch link", http.StatusBadGateway)
		return
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	publicLink := scheme + "://" + r.Host + "/time-punch/" + url.PathEscape(token)
	if err := renderHTMLTemplate(w, s.timePunchTmpl, pageData{
		Location:                 location,
		CSRF:                     csrfToken,
		Employees:                employees,
		TimePunchEntries:         entries,
		ArchivedTimePunchEntries: archivedEntries,
		TimePunchLink:            publicLink,
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
		http.Error(w, "unable to load time off requests", http.StatusBadGateway)
		return
	}
	employees, err := s.fetchLocationEmployees(r, locationNumber)
	if err != nil {
		http.Error(w, "unable to load location employees", http.StatusBadGateway)
		return
	}
	archivedRequests, err := s.fetchLocationTimeOffRequests(r, locationNumber, true)
	if err != nil {
		http.Error(w, "unable to load archived time off requests", http.StatusBadGateway)
		return
	}
	token, err := s.fetchLocationTimeOffToken(r, locationNumber)
	if err != nil {
		http.Error(w, "unable to load time off link", http.StatusBadGateway)
		return
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	publicLink := scheme + "://" + r.Host + "/time-off/" + url.PathEscape(token)
	if err := renderHTMLTemplate(w, s.timeOffTmpl, pageData{
		Location:                location,
		CSRF:                    csrfToken,
		Employees:               employees,
		TimeOffRequests:         requests,
		ArchivedTimeOffRequests: archivedRequests,
		TimeOffLink:             publicLink,
		SuccessMessage:          r.URL.Query().Get("message"),
		Error:                   r.URL.Query().Get("error"),
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
	orders, err := s.fetchLocationUniformOrders(r, locationNumber, false)
	if err != nil {
		http.Error(w, "unable to load uniform orders", http.StatusBadGateway)
		return
	}
	token, err := s.fetchLocationUniformToken(r, locationNumber)
	if err != nil {
		http.Error(w, "unable to load uniform order link", http.StatusBadGateway)
		return
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	publicLink := scheme + "://" + r.Host + "/uniform-order/" + url.PathEscape(token)
	if err := renderHTMLTemplate(w, s.uniformsTmpl, pageData{
		Location:       location,
		CSRF:           csrfToken,
		UniformItems:   items,
		UniformOrders:  orders,
		UniformLink:    publicLink,
		SuccessMessage: r.URL.Query().Get("message"),
		Error:          r.URL.Query().Get("error"),
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
		"name":  strings.TrimSpace(r.FormValue("name")),
		"price": strings.TrimSpace(r.FormValue("price")),
		"sizes": strings.TrimSpace(r.FormValue("sizes")),
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
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/time-punch?error=Unable+to+archive+entry#view-punches", http.StatusFound)
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
		msg := "unable to archive time punch entry"
		var payload map[string]string
		if err := json.Unmarshal(respBody, &payload); err == nil && strings.TrimSpace(payload["error"]) != "" {
			msg = payload["error"]
		}
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/time-punch?error="+url.QueryEscape(msg)+"#view-punches", http.StatusFound)
		return
	}
	http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/time-punch?message="+url.QueryEscape("Time punch entry archived")+"#view-punches", http.StatusFound)
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
	payload := map[string]string{
		"timePunchName": strings.TrimSpace(r.FormValue("time_punch_name")),
		"punchDate":     strings.TrimSpace(r.FormValue("punch_date")),
		"timeIn":        strings.TrimSpace(r.FormValue("time_in")),
		"timeOut":       strings.TrimSpace(r.FormValue("time_out")),
		"note":          strings.TrimSpace(r.FormValue("note")),
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
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/time-off?error=Unable+to+archive+request#view-requests", http.StatusFound)
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
		msg := "unable to archive time off request"
		var errPayload map[string]string
		if err := json.Unmarshal(respBody, &errPayload); err == nil && strings.TrimSpace(errPayload["error"]) != "" {
			msg = errPayload["error"]
		}
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/time-off?error="+url.QueryEscape(msg)+"#view-requests", http.StatusFound)
		return
	}
	http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/time-off?message="+url.QueryEscape("Time off request archived")+"#view-requests", http.StatusFound)
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
		msg := "unable to create time off request"
		var errPayload map[string]string
		if err := json.Unmarshal(respBody, &errPayload); err == nil && strings.TrimSpace(errPayload["error"]) != "" {
			msg = errPayload["error"]
		}
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/time-off?error="+url.QueryEscape(msg)+"#create-request", http.StatusFound)
		return
	}
	http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/time-off?message="+url.QueryEscape("Time off request submitted")+"#view-requests", http.StatusFound)
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
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees?error=Invalid+upload", http.StatusFound)
		return
	}
	file, header, err := r.FormFile("bio_file")
	if err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees?error=Employee+Bio+Reader+file+is+required", http.StatusFound)
		return
	}
	defer file.Close()

	csrfToken := strings.TrimSpace(r.FormValue("csrf_token"))
	if csrfToken == "" {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees?error=Missing+csrf+token", http.StatusFound)
		return
	}

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("bio_file", header.Filename)
	if err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees?error=Unable+to+prepare+upload", http.StatusFound)
		return
	}
	if _, err := io.Copy(part, file); err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees?error=Unable+to+read+upload", http.StatusFound)
		return
	}
	if err := writer.Close(); err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees?error=Unable+to+finalize+upload", http.StatusFound)
		return
	}

	apiURL := s.apiBaseURL + "/api/admin/locations/" + url.PathEscape(locationNumber) + "/employees/import"
	apiReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, apiURL, &body)
	if err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees?error=Unable+to+send+upload", http.StatusFound)
		return
	}
	copySessionCookieHeader(r, apiReq)
	apiReq.Header.Set("Content-Type", writer.FormDataContentType())
	apiReq.Header.Set(csrfHeaderName, csrfToken)

	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees?error=Import+service+unavailable", http.StatusFound)
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
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees?error="+url.QueryEscape(msg), http.StatusFound)
		return
	}

	http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees?message="+url.QueryEscape("Bio reader imported successfully"), http.StatusFound)
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
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees?error=Invalid+upload", http.StatusFound)
		return
	}
	file, header, err := r.FormFile("birthdate_file")
	if err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees?error=Birthday+report+file+is+required", http.StatusFound)
		return
	}
	defer file.Close()

	csrfToken := strings.TrimSpace(r.FormValue("csrf_token"))
	if csrfToken == "" {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees?error=Missing+csrf+token", http.StatusFound)
		return
	}

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("birthdate_file", header.Filename)
	if err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees?error=Unable+to+prepare+upload", http.StatusFound)
		return
	}
	if _, err := io.Copy(part, file); err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees?error=Unable+to+read+upload", http.StatusFound)
		return
	}
	if err := writer.Close(); err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees?error=Unable+to+finalize+upload", http.StatusFound)
		return
	}

	apiURL := s.apiBaseURL + "/api/admin/locations/" + url.PathEscape(locationNumber) + "/employees/birthdates/import"
	apiReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, apiURL, &body)
	if err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees?error=Unable+to+send+upload", http.StatusFound)
		return
	}
	copySessionCookieHeader(r, apiReq)
	apiReq.Header.Set("Content-Type", writer.FormDataContentType())
	apiReq.Header.Set(csrfHeaderName, csrfToken)

	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees?error=Import+service+unavailable", http.StatusFound)
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
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees?error="+url.QueryEscape(msg), http.StatusFound)
		return
	}

	http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees?message="+url.QueryEscape("Birthday report imported successfully"), http.StatusFound)
}

func (s *server) createEmployeeProxy(w http.ResponseWriter, r *http.Request, locationNumber string) {
	if err := r.ParseMultipartForm(20 << 20); err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees?error=Invalid+employee+form", http.StatusFound)
		return
	}
	csrfToken := strings.TrimSpace(r.FormValue("csrf_token"))
	if csrfToken == "" {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees?error=Missing+csrf+token", http.StatusFound)
		return
	}
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	for _, key := range []string{"first_name", "last_name", "department", "birthday"} {
		_ = writer.WriteField(key, strings.TrimSpace(r.FormValue(key)))
	}
	for _, fileField := range []string{"i9_file", "w4_file"} {
		file, header, err := r.FormFile(fileField)
		if err != nil {
			continue
		}
		part, err := writer.CreateFormFile(fileField, header.Filename)
		if err != nil {
			file.Close()
			http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees?error=Unable+to+prepare+upload", http.StatusFound)
			return
		}
		if _, err := io.Copy(part, file); err != nil {
			file.Close()
			http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees?error=Unable+to+read+upload", http.StatusFound)
			return
		}
		file.Close()
	}
	if err := writer.Close(); err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees?error=Unable+to+finalize+upload", http.StatusFound)
		return
	}

	apiURL := s.apiBaseURL + "/api/admin/locations/" + url.PathEscape(locationNumber) + "/employees"
	apiReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, apiURL, &body)
	if err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees?error=Unable+to+create+employee", http.StatusFound)
		return
	}
	copySessionCookieHeader(r, apiReq)
	apiReq.Header.Set("Content-Type", writer.FormDataContentType())
	apiReq.Header.Set(csrfHeaderName, csrfToken)
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees?error=Service+unavailable", http.StatusFound)
		return
	}
	defer apiResp.Body.Close()
	respBody, _ := io.ReadAll(apiResp.Body)
	if apiResp.StatusCode != http.StatusCreated && apiResp.StatusCode != http.StatusOK {
		msg := "unable to create employee"
		var payload map[string]string
		if err := json.Unmarshal(respBody, &payload); err == nil && strings.TrimSpace(payload["error"]) != "" {
			msg = payload["error"]
		}
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees?error="+url.QueryEscape(msg), http.StatusFound)
		return
	}
	type createEmployeeResponse struct {
		Message  string       `json:"message"`
		Employee employeeView `json:"employee"`
	}
	var payload createEmployeeResponse
	if err := json.Unmarshal(respBody, &payload); err == nil && strings.TrimSpace(payload.Employee.TimePunchName) != "" {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees/"+url.PathEscape(payload.Employee.TimePunchName)+"?message="+url.QueryEscape("Employee created"), http.StatusFound)
		return
	}
	http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees?message="+url.QueryEscape("Employee created"), http.StatusFound)
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

func (s *server) getEmployeeW4FileProxy(w http.ResponseWriter, r *http.Request) {
	apiPath, ok := mapEmployeeW4FilePathToAPI(r.URL.Path)
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
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees/"+url.PathEscape(timePunchName)+"?error=Invalid+form+submission", http.StatusFound)
		return
	}
	csrfToken := strings.TrimSpace(r.FormValue("csrf_token"))
	if csrfToken == "" {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees/"+url.PathEscape(timePunchName)+"?error=Missing+csrf+token", http.StatusFound)
		return
	}
	values := url.Values{}
	for key, items := range r.PostForm {
		if key == "csrf_token" {
			continue
		}
		for _, item := range items {
			values.Add(key, item)
		}
	}
	body := strings.NewReader(values.Encode())
	apiURL := s.apiBaseURL + "/api/admin/locations/" + url.PathEscape(locationNumber) + "/employees/" + url.PathEscape(timePunchName) + "/i9"
	apiReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, apiURL, body)
	if err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees/"+url.PathEscape(timePunchName)+"?error=Unable+to+send+upload", http.StatusFound)
		return
	}
	copySessionCookieHeader(r, apiReq)
	apiReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	apiReq.Header.Set(csrfHeaderName, csrfToken)
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees/"+url.PathEscape(timePunchName)+"?error=Service+unavailable", http.StatusFound)
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
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees/"+url.PathEscape(timePunchName)+"?error="+url.QueryEscape(msg), http.StatusFound)
		return
	}
	http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees/"+url.PathEscape(timePunchName)+"?message="+url.QueryEscape("I-9 generated and saved"), http.StatusFound)
}

func (s *server) uploadEmployeeW4Proxy(w http.ResponseWriter, r *http.Request, locationNumber, timePunchName string) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees/"+url.PathEscape(timePunchName)+"?error=Invalid+form+submission", http.StatusFound)
		return
	}
	csrfToken := strings.TrimSpace(r.FormValue("csrf_token"))
	if csrfToken == "" {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees/"+url.PathEscape(timePunchName)+"?error=Missing+csrf+token", http.StatusFound)
		return
	}
	values := url.Values{}
	for key, items := range r.PostForm {
		if key == "csrf_token" {
			continue
		}
		for _, item := range items {
			values.Add(key, item)
		}
	}
	body := strings.NewReader(values.Encode())
	apiURL := s.apiBaseURL + "/api/admin/locations/" + url.PathEscape(locationNumber) + "/employees/" + url.PathEscape(timePunchName) + "/w4"
	apiReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, apiURL, body)
	if err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees/"+url.PathEscape(timePunchName)+"?error=Unable+to+send+upload", http.StatusFound)
		return
	}
	copySessionCookieHeader(r, apiReq)
	apiReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	apiReq.Header.Set(csrfHeaderName, csrfToken)
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees/"+url.PathEscape(timePunchName)+"?error=Service+unavailable", http.StatusFound)
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
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees/"+url.PathEscape(timePunchName)+"?error="+url.QueryEscape(msg), http.StatusFound)
		return
	}
	http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees/"+url.PathEscape(timePunchName)+"?message="+url.QueryEscape("W-4 generated and saved"), http.StatusFound)
}

func (s *server) uploadEmployeeI9DocumentProxy(w http.ResponseWriter, r *http.Request, locationNumber, timePunchName string) {
	if err := r.ParseMultipartForm(20 << 20); err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees/"+url.PathEscape(timePunchName)+"?error=Invalid+upload", http.StatusFound)
		return
	}
	csrfToken := strings.TrimSpace(r.FormValue("csrf_token"))
	if csrfToken == "" {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees/"+url.PathEscape(timePunchName)+"?error=Missing+csrf+token", http.StatusFound)
		return
	}
	file, header, err := r.FormFile("document_file")
	if err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees/"+url.PathEscape(timePunchName)+"?error=Document+file+is+required", http.StatusFound)
		return
	}
	defer file.Close()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("document_file", header.Filename)
	if err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees/"+url.PathEscape(timePunchName)+"?error=Unable+to+prepare+upload", http.StatusFound)
		return
	}
	if _, err := io.Copy(part, file); err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees/"+url.PathEscape(timePunchName)+"?error=Unable+to+read+upload", http.StatusFound)
		return
	}
	if err := writer.Close(); err != nil {
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees/"+url.PathEscape(timePunchName)+"?error=Unable+to+finalize+upload", http.StatusFound)
		return
	}
	apiURL := s.apiBaseURL + "/api/admin/locations/" + url.PathEscape(locationNumber) + "/employees/" + url.PathEscape(timePunchName) + "/i9/documents"
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
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees/"+url.PathEscape(timePunchName)+"?error=Service+unavailable", http.StatusFound)
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
		http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees/"+url.PathEscape(timePunchName)+"?error="+url.QueryEscape(msg), http.StatusFound)
		return
	}
	http.Redirect(w, r, "/admin/locations/"+url.PathEscape(locationNumber)+"/employees/"+url.PathEscape(timePunchName)+"?message="+url.QueryEscape("I-9 document uploaded"), http.StatusFound)
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
	apiURL := s.apiBaseURL + "/api/public/time-punch/" + url.PathEscape(token)
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
	if apiResp.StatusCode != http.StatusOK {
		http.NotFound(w, r)
		return
	}
	var payload publicTimePunchResponse
	if err := json.NewDecoder(apiResp.Body).Decode(&payload); err != nil {
		http.Error(w, "invalid response", http.StatusBadGateway)
		return
	}
	if err := renderHTMLTemplate(w, s.publicTimePunchTmpl, pageData{
		Token:          token,
		Location:       &locationView{Number: payload.LocationNumber, Name: payload.LocationName},
		Employees:      payload.Employees,
		SuccessMessage: r.URL.Query().Get("message"),
		Error:          r.URL.Query().Get("error"),
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
	payload := map[string]string{
		"timePunchName": strings.TrimSpace(r.FormValue("time_punch_name")),
		"punchDate":     strings.TrimSpace(r.FormValue("punch_date")),
		"timeIn":        strings.TrimSpace(r.FormValue("time_in")),
		"timeOut":       strings.TrimSpace(r.FormValue("time_out")),
		"note":          strings.TrimSpace(r.FormValue("note")),
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
	apiURL := s.apiBaseURL + "/api/public/time-off/" + url.PathEscape(token)
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
	if apiResp.StatusCode != http.StatusOK {
		http.NotFound(w, r)
		return
	}
	var payload publicTimeOffResponse
	if err := json.NewDecoder(apiResp.Body).Decode(&payload); err != nil {
		http.Error(w, "invalid response", http.StatusBadGateway)
		return
	}
	if err := renderHTMLTemplate(w, s.publicTimeOffTmpl, pageData{
		Token:          token,
		Location:       &locationView{Number: payload.LocationNumber, Name: payload.LocationName},
		Employees:      payload.Employees,
		SuccessMessage: r.URL.Query().Get("message"),
		Error:          r.URL.Query().Get("error"),
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
	payload := map[string]string{
		"timePunchName": strings.TrimSpace(r.FormValue("time_punch_name")),
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
		msg := "unable to submit time off request"
		var errPayload map[string]string
		if err := json.Unmarshal(respBody, &errPayload); err == nil && strings.TrimSpace(errPayload["error"]) != "" {
			msg = errPayload["error"]
		}
		http.Redirect(w, r, "/time-off/"+url.PathEscape(token)+"?error="+url.QueryEscape(msg), http.StatusFound)
		return
	}
	http.Redirect(w, r, "/time-off/"+url.PathEscape(token)+"?message="+url.QueryEscape("Time off request submitted"), http.StatusFound)
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
	if err := renderHTMLTemplate(w, s.publicUniformItemTmpl, pageData{
		Token:          token,
		Location:       &locationView{Number: payload.LocationNumber, Name: payload.LocationName},
		Employees:      payload.Employees,
		UniformItem:    selected,
		SuccessMessage: r.URL.Query().Get("message"),
		Error:          r.URL.Query().Get("error"),
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
	payload := map[string]any{
		"timePunchName": strings.TrimSpace(r.FormValue("time_punch_name")),
		"items": []map[string]any{
			{
				"itemId":   itemID,
				"size":     strings.TrimSpace(r.FormValue("size")),
				"note":     strings.TrimSpace(r.FormValue("note")),
				"quantity": quantity,
			},
		},
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

func (s *server) requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.sessionIsValid(r) {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *server) sessionIsValid(r *http.Request) bool {
	apiReq, err := http.NewRequestWithContext(r.Context(), http.MethodGet, s.apiBaseURL+"/api/auth/me", nil)
	if err != nil {
		return false
	}
	copySessionCookieHeader(r, apiReq)

	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		return false
	}
	defer apiResp.Body.Close()

	return apiResp.StatusCode == http.StatusOK
}

func (s *server) fetchCSRFToken(r *http.Request) (string, error) {
	apiReq, err := http.NewRequestWithContext(r.Context(), http.MethodGet, s.apiBaseURL+"/api/auth/csrf", nil)
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
		payload.Entries[i].ArchivedAt = formatDateTimeDisplay(payload.Entries[i].ArchivedAt)
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

func (s *server) fetchEmployeePaperwork(r *http.Request, locationNumber, timePunchName string, archived bool, paperworkType string) (*employeeI9View, []employeeI9DocumentView, error) {
	apiURL := s.apiBaseURL + "/api/admin/locations/" + url.PathEscape(locationNumber)
	if archived {
		apiURL += "/employees/archived/" + url.PathEscape(timePunchName) + "/" + url.PathEscape(strings.ToLower(strings.TrimSpace(paperworkType)))
	} else {
		apiURL += "/employees/" + url.PathEscape(timePunchName) + "/" + url.PathEscape(strings.ToLower(strings.TrimSpace(paperworkType)))
	}
	apiReq, err := http.NewRequestWithContext(r.Context(), http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, nil, err
	}
	copySessionCookieHeader(r, apiReq)
	apiResp, err := s.apiClient.Do(apiReq)
	if err != nil {
		return nil, nil, err
	}
	defer apiResp.Body.Close()
	if apiResp.StatusCode != http.StatusOK {
		return nil, nil, errors.New("failed to fetch employee paperwork records")
	}
	var payload employeePaperworkResponse
	if err := json.NewDecoder(apiResp.Body).Decode(&payload); err != nil {
		return nil, nil, err
	}
	normalizeEmployeePaperworkView(&payload.Paperwork)
	for i := range payload.Documents {
		payload.Documents[i].CreatedAt = formatDateTimeDisplay(payload.Documents[i].CreatedAt)
	}
	return &payload.Paperwork, payload.Documents, nil
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
	question.CreatedAt = formatDateTimeDisplay(question.CreatedAt)
	question.UpdatedAt = formatDateTimeDisplay(question.UpdatedAt)
}

func normalizeCandidateInterviewLinkView(link *candidateInterviewLinkView) {
	link.CreatedAt = formatDateTimeDisplay(link.CreatedAt)
	link.ExpiresAt = formatDateTimeDisplay(link.ExpiresAt)
	link.UsedAt = formatDateTimeDisplay(link.UsedAt)
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

func copySessionCookieHeader(from *http.Request, to *http.Request) {
	for _, c := range from.Cookies() {
		if c.Name == sessionCookieName {
			to.Header.Set("Cookie", c.Name+"="+c.Value)
			return
		}
	}
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

func parseLocationEmployeeCreatePath(path string) (string, bool) {
	trimmed := strings.TrimPrefix(path, "/admin/locations/")
	trimmed = strings.Trim(trimmed, "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) != 3 || parts[1] != "employees" || parts[2] != "create" {
		return "", false
	}
	locationNumber, err := url.PathUnescape(parts[0])
	if err != nil || strings.TrimSpace(locationNumber) == "" {
		return "", false
	}
	return locationNumber, true
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

func parseLocationEmployeeI9UploadPath(path string) (string, string, bool) {
	return parseLocationEmployeeActionPath(path, "i9")
}

func parseLocationEmployeeW4UploadPath(path string) (string, string, bool) {
	return parseLocationEmployeeActionPath(path, "w4")
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
