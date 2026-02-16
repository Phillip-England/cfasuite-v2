package apiapp

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	stddraw "image/draw"
	"image/png"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/extrame/xls"
	"github.com/phillip-england/cfasuite/internal/middleware"
	"github.com/phillip-england/cfasuite/internal/security"
	"github.com/xuri/excelize/v2"
	xdraw "golang.org/x/image/draw"
	"golang.org/x/image/webp"
	_ "image/jpeg"
)

const (
	sessionCookieName = "cfasuite_session"
	csrfHeaderName    = "X-CSRF-Token"
	defaultPerPage    = 25
	maxPerPage        = 25
)

var errNotFound = errors.New("not found")

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

type createLocationRequest struct {
	Name   string `json:"name"`
	Number string `json:"number"`
}

type updateLocationRequest struct {
	Name string `json:"name"`
}

type updateEmployeeDepartmentRequest struct {
	Department string `json:"department"`
}

type createTimePunchEntryRequest struct {
	TimePunchName string `json:"timePunchName"`
	PunchDate     string `json:"punchDate"`
	TimeIn        string `json:"timeIn"`
	TimeOut       string `json:"timeOut"`
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
	Name  string `json:"name"`
	Price string `json:"price"`
	Sizes string `json:"sizes"`
}

type updateUniformItemRequest struct {
	Name  string `json:"name"`
	Price string `json:"price"`
	Sizes string `json:"sizes"`
}

type createUniformOrderRequest struct {
	TimePunchName string                          `json:"timePunchName"`
	Items         []createUniformOrderLineRequest `json:"items"`
}

type createUniformOrderLineRequest struct {
	ItemID   int64  `json:"itemId"`
	Size     string `json:"size,omitempty"`
	Note     string `json:"note,omitempty"`
	Quantity int64  `json:"quantity"`
}

type moveUniformImageRequest struct {
	Direction string `json:"direction"`
}

type updateUniformOrderLineSettlementRequest struct {
	Purchased   bool   `json:"purchased"`
	ChargedBack string `json:"chargedBack"`
}

type userRecord struct {
	ID       int64
	Username string
	IsAdmin  bool
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
	CreatedAt time.Time `json:"createdAt"`
}

type employee struct {
	FirstName     string `json:"firstName"`
	LastName      string `json:"lastName"`
	TimePunchName string `json:"timePunchName"`
	Department    string `json:"department"`
	Birthday      string `json:"birthday,omitempty"`
	HasPhoto      bool   `json:"hasPhoto"`
	ArchivedAt    string `json:"archivedAt,omitempty"`
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
	FileName       string    `json:"fileName"`
	FileMime       string    `json:"fileMime"`
	CreatedAt      time.Time `json:"createdAt"`
}

type archivedEmployeeRecord struct {
	ID             int64
	LocationNumber string
	TimePunchName  string
	FirstName      string
	LastName       string
	Department     string
	Birthday       string
	ProfileImage   string
	ProfileMime    string
	ArchivedAt     time.Time
}

var allowedDepartments = map[string]struct{}{
	"INIT":       {},
	"NONE":       {},
	"FOH":        {},
	"BOH":        {},
	"LEADERSHIP": {},
	"RLT":        {},
	"CST":        {},
	"EXECUTIVE":  {},
	"PARTNER":    {},
	"OPERATOR":   {},
}

type bioEmployeeRow struct {
	FirstName     string
	LastName      string
	TimePunchName string
	Terminated    bool
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

type locationTimePunchToken struct {
	Token          string
	LocationNumber string
}

type locationTimeOffToken struct {
	Token          string
	LocationNumber string
}

type timePunchEntry struct {
	ID            int64     `json:"id"`
	LocationNum   string    `json:"locationNumber"`
	TimePunchName string    `json:"timePunchName"`
	PunchDate     string    `json:"punchDate"`
	TimeIn        string    `json:"timeIn"`
	TimeOut       string    `json:"timeOut"`
	CreatedAt     time.Time `json:"createdAt"`
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
	CreatedAt   time.Time          `json:"createdAt"`
	UpdatedAt   time.Time          `json:"updatedAt"`
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
	SizeOption  string    `json:"sizeOption"`
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
	Size           string
	Note           string
	Quantity       int64
	UnitPriceCents int64
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
	if err := s.store.ensureAdminUser(ctx, cfg.AdminUsername, cfg.AdminPassword); err != nil {
		return fmt.Errorf("ensure admin user: %w", err)
	}
	mux := http.NewServeMux()
	mux.Handle("/api/health", http.HandlerFunc(s.health))
	mux.Handle("/api/auth/login", http.HandlerFunc(s.login))
	mux.Handle("/api/auth/me", middleware.Chain(http.HandlerFunc(s.me), s.requireAdmin))
	mux.Handle("/api/auth/csrf", middleware.Chain(http.HandlerFunc(s.csrfToken), s.requireAdmin))
	mux.Handle("/api/auth/logout", middleware.Chain(http.HandlerFunc(s.logout), s.requireAdmin, s.csrfProtect))
	mux.Handle("/api/admin/locations", middleware.Chain(http.HandlerFunc(s.locationsHandler), s.requireAdmin, s.csrfProtect))
	mux.Handle("/api/admin/locations/", middleware.Chain(http.HandlerFunc(s.locationByNumberHandler), s.requireAdmin, s.csrfProtect))
	mux.Handle("/api/public/employee-photo-upload/", http.HandlerFunc(s.publicEmployeePhotoUploadHandler))
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

	if !user.IsAdmin || !security.VerifyPassword(req.Password, hash) {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	sessionID, err := randomToken(32)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "authentication failed")
		return
	}
	csrfToken, err := randomToken(32)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "authentication failed")
		return
	}

	expires := time.Now().UTC().Add(s.sessionTTL)
	if err := s.store.createSession(r.Context(), sessionID, user.ID, csrfToken, expires); err != nil {
		writeError(w, http.StatusInternalServerError, "authentication failed")
		return
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
	writeJSON(w, http.StatusOK, map[string]string{"message": "authenticated"})
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
		"id":       user.ID,
		"username": user.Username,
		"isAdmin":  user.IsAdmin,
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

func (s *server) locationsHandler(w http.ResponseWriter, r *http.Request) {
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

	if len(parts) == 2 && parts[1] == "employees" {
		switch r.Method {
		case http.MethodGet:
			s.listLocationEmployees(w, r, locationNumber)
			return
		case http.MethodPost:
			s.createLocationEmployee(w, r, locationNumber)
			return
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
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
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.listLocationTimePunchEntries(w, r, locationNumber)
		return
	}

	if len(parts) == 2 && parts[1] == "time-off" {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.listLocationTimeOffRequests(w, r, locationNumber)
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
		var req createTimePunchEntryRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request body")
			return
		}
		req.TimePunchName = strings.TrimSpace(req.TimePunchName)
		req.PunchDate = strings.TrimSpace(req.PunchDate)
		req.TimeIn = strings.TrimSpace(req.TimeIn)
		req.TimeOut = strings.TrimSpace(req.TimeOut)
		if err := validateCreateTimePunchEntry(req); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if _, err := s.store.getLocationEmployee(r.Context(), record.LocationNumber, req.TimePunchName); err != nil {
			if errors.Is(err, errNotFound) {
				writeError(w, http.StatusBadRequest, "employee not found for this location")
				return
			}
			writeError(w, http.StatusInternalServerError, "unable to validate employee")
			return
		}
		err := withSQLiteRetry(func() error {
			return s.store.createTimePunchEntry(r.Context(), timePunchEntry{
				LocationNum:   record.LocationNumber,
				TimePunchName: req.TimePunchName,
				PunchDate:     req.PunchDate,
				TimeIn:        req.TimeIn,
				TimeOut:       req.TimeOut,
				CreatedAt:     time.Now().UTC(),
			})
		})
		if err != nil {
			writeError(w, http.StatusInternalServerError, "unable to save time punch entry")
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"message": "time punch correction submitted"})
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
		if _, err := s.store.getLocationEmployee(r.Context(), record.LocationNumber, strings.TrimSpace(req.TimePunchName)); err != nil {
			if errors.Is(err, errNotFound) {
				writeError(w, http.StatusBadRequest, "employee not found for this location")
				return
			}
			writeError(w, http.StatusInternalServerError, "unable to validate employee")
			return
		}
		err = withSQLiteRetry(func() error {
			return s.store.createTimeOffRequest(r.Context(), timeOffRequest{
				LocationNum:   record.LocationNumber,
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
		if _, err := s.store.getLocationEmployee(r.Context(), record.LocationNumber, req.TimePunchName); err != nil {
			if errors.Is(err, errNotFound) {
				writeError(w, http.StatusBadRequest, "employee not found for this location")
				return
			}
			writeError(w, http.StatusInternalServerError, "unable to validate employee")
			return
		}
		enabledItems, err := s.store.listUniformItems(r.Context(), record.LocationNumber, false)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "unable to validate uniform items")
			return
		}
		itemsByID := make(map[int64]uniformItem, len(enabledItems))
		for _, item := range enabledItems {
			itemsByID[item.ID] = item
		}
		lineItems := make([]uniformOrderLineInput, 0, len(req.Items))
		for _, line := range req.Items {
			item, ok := itemsByID[line.ItemID]
			if !ok {
				writeError(w, http.StatusBadRequest, "one or more selected uniform items are invalid")
				return
			}
			if line.Quantity <= 0 {
				writeError(w, http.StatusBadRequest, "quantity must be at least 1")
				return
			}
			lineSize := strings.TrimSpace(line.Size)
			if len(item.Sizes) > 0 {
				if lineSize == "" || !containsIgnoreCase(item.Sizes, lineSize) {
					writeError(w, http.StatusBadRequest, "invalid size selected for one or more items")
					return
				}
			} else {
				lineSize = ""
			}
			unitCents, err := parsePriceToCents(fmt.Sprintf("%.2f", item.Price))
			if err != nil {
				writeError(w, http.StatusInternalServerError, "unable to calculate item totals")
				return
			}
			lineItems = append(lineItems, uniformOrderLineInput{
				ItemID:         item.ID,
				ItemName:       item.Name,
				Size:           lineSize,
				Note:           strings.TrimSpace(line.Note),
				Quantity:       line.Quantity,
				UnitPriceCents: unitCents,
			})
		}
		if len(lineItems) == 0 {
			writeError(w, http.StatusBadRequest, "at least one uniform item must be selected")
			return
		}

		err = withSQLiteRetry(func() error {
			return s.store.createUniformOrder(r.Context(), record.LocationNumber, req.TimePunchName, lineItems)
		})
		if err != nil {
			writeError(w, http.StatusInternalServerError, "unable to save uniform order")
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"message": "uniform order submitted"})
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
		Name:  strings.TrimSpace(r.FormValue("name")),
		Price: strings.TrimSpace(r.FormValue("price")),
		Sizes: strings.TrimSpace(r.FormValue("sizes")),
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
	sizes := parseUniformSizes(req.Sizes)

	item := uniformItem{
		LocationNum: number,
		Name:        req.Name,
		Price:       float64(priceCents) / 100.0,
		Enabled:     true,
		ImageData:   base64.StdEncoding.EncodeToString(raw),
		ImageMime:   mime,
		Images:      images,
		Sizes:       sizes,
		CreatedAt:   time.Now().UTC(),
		UpdatedAt:   time.Now().UTC(),
	}
	err = withSQLiteRetry(func() error {
		return s.store.createUniformItem(r.Context(), item, priceCents, sizes)
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
	var req updateUniformItemRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	req.Sizes = strings.TrimSpace(req.Sizes)
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "item name is required")
		return
	}
	priceCents, err := parsePriceToCents(req.Price)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := withSQLiteRetry(func() error {
		return s.store.updateUniformItem(r.Context(), number, itemID, req.Name, priceCents, parseUniformSizes(req.Sizes))
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

func (s *server) moveLocationUniformItemImage(w http.ResponseWriter, r *http.Request, number string, itemID, imageID int64) {
	if _, err := s.store.getLocationByNumber(r.Context(), number); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "location not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load location")
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
	if _, err := s.store.getUniformItemByID(r.Context(), number, itemID); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "uniform item not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load uniform item")
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

func (s *server) createLocationEmployee(w http.ResponseWriter, r *http.Request, number string) {
	if _, err := s.store.getLocationByNumber(r.Context(), number); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "location not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load location")
		return
	}
	if err := r.ParseMultipartForm(20 << 20); err != nil {
		writeError(w, http.StatusBadRequest, "invalid form data")
		return
	}
	firstName := strings.TrimSpace(r.FormValue("first_name"))
	lastName := strings.TrimSpace(r.FormValue("last_name"))
	if firstName == "" || lastName == "" {
		writeError(w, http.StatusBadRequest, "first name and last name are required")
		return
	}
	department := normalizeDepartment(strings.TrimSpace(r.FormValue("department")))
	if _, ok := allowedDepartments[department]; !ok {
		department = "INIT"
	}
	birthday := strings.TrimSpace(r.FormValue("birthday"))
	if birthday != "" {
		if normalized, ok := normalizeBirthday(birthday); ok {
			birthday = normalized
		} else {
			writeError(w, http.StatusBadRequest, "birthday must be a valid date")
			return
		}
	}
	timePunchName := canonicalTimePunchName(firstName, lastName)
	if strings.TrimSpace(timePunchName) == "" {
		writeError(w, http.StatusBadRequest, "unable to build time punch name")
		return
	}
	if _, err := s.store.getLocationEmployee(r.Context(), number, timePunchName); err == nil {
		writeError(w, http.StatusConflict, "employee already exists")
		return
	} else if !errors.Is(err, errNotFound) {
		writeError(w, http.StatusInternalServerError, "unable to check existing employees")
		return
	}

	newEmployee := employee{
		FirstName:     firstName,
		LastName:      lastName,
		TimePunchName: timePunchName,
		Department:    department,
		Birthday:      birthday,
	}
	if err := withSQLiteRetry(func() error {
		return s.store.upsertLocationEmployee(r.Context(), number, newEmployee)
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "unable to create employee")
		return
	}

	i9Data, i9Mime, i9Name, i9Provided, err := parseOptionalUploadedFileWithField(r, "i9_file", 10<<20, []string{"application/pdf"})
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if i9Provided {
		if err := withSQLiteRetry(func() error {
			return s.store.upsertEmployeeI9Form(r.Context(), number, timePunchName, i9Data, i9Mime, i9Name)
		}); err != nil {
			writeError(w, http.StatusInternalServerError, "unable to persist i9")
			return
		}
	}

	w4Data, w4Mime, w4Name, w4Provided, err := parseOptionalUploadedFileWithField(r, "w4_file", 10<<20, []string{"application/pdf"})
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if w4Provided {
		if err := withSQLiteRetry(func() error {
			return s.store.upsertEmployeeW4Form(r.Context(), number, timePunchName, w4Data, w4Mime, w4Name)
		}); err != nil {
			writeError(w, http.StatusInternalServerError, "unable to persist w4")
			return
		}
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"message":  "employee created",
		"employee": newEmployee,
	})
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
	entries, err := s.store.listTimePunchEntries(r.Context(), number)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to load time punch entries")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"count":   len(entries),
		"entries": entries,
	})
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
		writeError(w, http.StatusInternalServerError, "unable to archive time off request")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "time off request archived"})
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
	writeJSON(w, http.StatusOK, map[string]any{
		"i9":        form,
		"paperwork": form,
		"documents": docs,
	})
}

func (s *server) uploadEmployeeI9(w http.ResponseWriter, r *http.Request, number, timePunchName string) {
	if _, err := s.store.getLocationEmployee(r.Context(), number, timePunchName); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "employee not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load employee")
		return
	}
	data, mime, fileName, provided, err := parseOptionalUploadedFileWithField(r, "i9_file", 10<<20, []string{"application/pdf"})
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid i9 upload")
		return
	}
	var formValues url.Values
	if !provided {
		if err := r.ParseForm(); err != nil {
			writeError(w, http.StatusBadRequest, "invalid i9 form")
			return
		}
		formValues = r.PostForm
		data, err = generateFilledI9PDF(r.PostForm)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		mime = "application/pdf"
		fileName = "i9-filled.pdf"
	}
	if err := withSQLiteRetry(func() error {
		return s.store.upsertEmployeeI9Form(r.Context(), number, timePunchName, data, mime, fileName)
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "unable to persist i9 form")
		return
	}
	if !provided && formValues != nil {
		drawnSignature := strings.TrimSpace(formValues.Get("employee_signature_drawn"))
		if drawnSignature != "" {
			imageData, imageMime, err := parseDataURLBinary(drawnSignature, []string{"image/png", "image/jpeg", "image/webp"}, 2<<20)
			if err != nil {
				writeError(w, http.StatusBadRequest, "invalid drawn signature")
				return
			}
			fileExt := ".png"
			if imageMime == "image/jpeg" {
				fileExt = ".jpg"
			} else if imageMime == "image/webp" {
				fileExt = ".webp"
			}
			signatureName := "i9-signature-" + time.Now().UTC().Format("20060102-150405") + fileExt
			if err := withSQLiteRetry(func() error {
				return s.store.addEmployeeI9Document(r.Context(), number, timePunchName, imageData, imageMime, signatureName)
			}); err != nil {
				writeError(w, http.StatusInternalServerError, "unable to persist drawn signature")
				return
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "i9 saved"})
}

func (s *server) getEmployeeI9File(w http.ResponseWriter, r *http.Request, number, timePunchName string) {
	data, mime, fileName, err := s.store.getEmployeeI9File(r.Context(), number, timePunchName)
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
	if _, err := s.store.getLocationEmployee(r.Context(), number, timePunchName); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "employee not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load employee")
		return
	}
	data, mime, fileName, err := parseUploadedFileWithField(r, "document_file", 10<<20, []string{"application/pdf", "image/png", "image/jpeg", "image/webp"}, "document file is required")
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := withSQLiteRetry(func() error {
		return s.store.addEmployeeI9Document(r.Context(), number, timePunchName, data, mime, fileName)
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "unable to persist i9 document")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"message": "document uploaded"})
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
	w.Header().Set("Cache-Control", "private, max-age=120")
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
	writeJSON(w, http.StatusOK, map[string]any{
		"paperwork": form,
	})
}

func (s *server) uploadEmployeeW4(w http.ResponseWriter, r *http.Request, number, timePunchName string) {
	if _, err := s.store.getLocationEmployee(r.Context(), number, timePunchName); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "employee not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load employee")
		return
	}
	data, mime, fileName, provided, err := parseOptionalUploadedFileWithField(r, "w4_file", 10<<20, []string{"application/pdf"})
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid w4 upload")
		return
	}
	if !provided {
		if err := r.ParseForm(); err != nil {
			writeError(w, http.StatusBadRequest, "invalid w4 form")
			return
		}
		data, err = generateFilledW4PDF(r.PostForm)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		mime = "application/pdf"
		fileName = "w4-filled.pdf"
	}
	if err := withSQLiteRetry(func() error {
		return s.store.upsertEmployeeW4Form(r.Context(), number, timePunchName, data, mime, fileName)
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "unable to persist w4 form")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "w4 saved"})
}

func (s *server) getEmployeeW4File(w http.ResponseWriter, r *http.Request, number, timePunchName string) {
	data, mime, fileName, err := s.store.getEmployeeW4File(r.Context(), number, timePunchName)
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
	for _, e := range existing {
		employeesByKey[e.TimePunchName] = e
	}

	activeByKey := make(map[string]bioEmployeeRow)
	for _, row := range parsedRows {
		if row.Terminated {
			continue
		}
		activeByKey[row.TimePunchName] = row
	}

	added := 0
	updated := 0
	archived := 0
	for key, incoming := range activeByKey {
		current, found := employeesByKey[key]
		if !found {
			newEmployee := employee{
				FirstName:     incoming.FirstName,
				LastName:      incoming.LastName,
				TimePunchName: incoming.TimePunchName,
				Department:    "INIT",
			}
			if err := withSQLiteRetry(func() error {
				return s.store.upsertLocationEmployee(r.Context(), number, newEmployee)
			}); err != nil {
				writeError(w, http.StatusInternalServerError, "unable to persist employees: "+err.Error())
				return
			}
			employeesByKey[key] = newEmployee
			added++
			continue
		}

		changed := false
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
			employeesByKey[key] = current
			updated++
		}
	}

	for _, existingEmployee := range existing {
		if _, ok := activeByKey[existingEmployee.TimePunchName]; ok {
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
		"message":  "employee bio reader imported",
		"added":    added,
		"updated":  updated,
		"archived": archived,
		"count":    len(activeByKey),
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
	if err := validateCreateLocation(req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	entry := location{
		Name:      strings.TrimSpace(req.Name),
		Number:    strings.TrimSpace(req.Number),
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
	writeJSON(w, http.StatusCreated, map[string]any{
		"message":  "location created",
		"location": entry,
	})
}

func (s *server) updateLocation(w http.ResponseWriter, r *http.Request, number string) {
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
	if _, ok := allowedDepartments[department]; !ok {
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

func (s *server) requireAdmin(next http.Handler) http.Handler {
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
		if !user.IsAdmin {
			expireSessionCookie(w)
			writeError(w, http.StatusForbidden, "admin access required")
			return
		}

		ctx := context.WithValue(r.Context(), sessionContextKey, sess)
		ctx = context.WithValue(ctx, userContextKey, user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
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
			created_at INTEGER NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS location_employees (
			location_number TEXT NOT NULL,
			time_punch_name TEXT NOT NULL,
			first_name TEXT NOT NULL,
			last_name TEXT NOT NULL,
			department TEXT NOT NULL DEFAULT 'INIT',
			birthday TEXT NOT NULL DEFAULT '',
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
			first_name TEXT NOT NULL,
			last_name TEXT NOT NULL,
			department TEXT NOT NULL DEFAULT 'INIT',
			birthday TEXT NOT NULL DEFAULT '',
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
		`CREATE TABLE IF NOT EXISTS employee_i9_documents (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			location_number TEXT NOT NULL,
			time_punch_name TEXT NOT NULL,
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
			size_option TEXT NOT NULL DEFAULT '',
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
		ADD COLUMN profile_image_mime TEXT NOT NULL DEFAULT '';
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
	_, err := s.exec(ctx, `DELETE FROM sessions WHERE expires_at <= @now;`, map[string]string{
		"now": strconv.FormatInt(time.Now().UTC().Unix(), 10),
	})
	return err
}

func (s *sqliteStore) ensureAdminUser(ctx context.Context, username, password string) error {
	hash, err := security.HashPassword(password)
	if err != nil {
		return err
	}

	_, err = s.exec(ctx, `
		INSERT INTO users (username, password_hash, is_admin, created_at)
		VALUES (@username, @password_hash, 1, @created_at)
		ON CONFLICT(username)
		DO UPDATE SET password_hash = excluded.password_hash, is_admin = 1;
	`, map[string]string{
		"username":      username,
		"password_hash": hash,
		"created_at":    strconv.FormatInt(time.Now().UTC().Unix(), 10),
	})
	return err
}

func (s *sqliteStore) createLocation(ctx context.Context, loc location) error {
	_, err := s.exec(ctx, `
		INSERT INTO locations (number, name, created_at)
		VALUES (@number, @name, @created_at);
	`, map[string]string{
		"number":     loc.Number,
		"name":       loc.Name,
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
		DELETE FROM locations
		WHERE number = @number;
		COMMIT;
	`
	_, err := s.exec(ctx, statement, map[string]string{"number": number})
	return err
}

func (s *sqliteStore) listLocations(ctx context.Context) ([]location, error) {
	rows, err := s.query(ctx, `
		SELECT name, number, created_at
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
		createdAtUnix, err := valueAsInt64(row["created_at"])
		if err != nil {
			return nil, err
		}
		out = append(out, location{
			Name:      name,
			Number:    number,
			CreatedAt: time.Unix(createdAtUnix, 0).UTC(),
		})
	}
	return out, nil
}

func (s *sqliteStore) getLocationByNumber(ctx context.Context, number string) (*location, error) {
	rows, err := s.query(ctx, `
		SELECT name, number, created_at
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
	createdAtUnix, err := valueAsInt64(rows[0]["created_at"])
	if err != nil {
		return nil, err
	}
	return &location{
		Name:      name,
		Number:    locNumber,
		CreatedAt: time.Unix(createdAtUnix, 0).UTC(),
	}, nil
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
		SELECT time_punch_name, first_name, last_name, department, birthday,
			CASE WHEN LENGTH(COALESCE(profile_image_data, '')) > 0 THEN 1 ELSE 0 END AS has_photo
		FROM location_employees
		WHERE location_number = @location_number;
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
		birthday, err := valueAsString(row["birthday"])
		if err != nil {
			return nil, err
		}
		hasPhotoRaw, err := valueAsInt64(row["has_photo"])
		if err != nil {
			return nil, err
		}
		employees = append(employees, employee{
			FirstName:     firstName,
			LastName:      lastName,
			TimePunchName: timePunchName,
			Department:    normalizeDepartment(department),
			Birthday:      birthday,
			HasPhoto:      hasPhotoRaw == 1,
		})
	}
	return employees, nil
}

func (s *sqliteStore) getLocationEmployee(ctx context.Context, locationNumber, timePunchName string) (*employee, error) {
	rows, err := s.query(ctx, `
		SELECT time_punch_name, first_name, last_name, department, birthday,
			CASE WHEN LENGTH(COALESCE(profile_image_data, '')) > 0 THEN 1 ELSE 0 END AS has_photo
		FROM location_employees
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
	birthday, err := valueAsString(rows[0]["birthday"])
	if err != nil {
		return nil, err
	}
	hasPhotoRaw, err := valueAsInt64(rows[0]["has_photo"])
	if err != nil {
		return nil, err
	}
	return &employee{
		FirstName:     firstName,
		LastName:      lastName,
		TimePunchName: tpn,
		Department:    normalizeDepartment(dept),
		Birthday:      birthday,
		HasPhoto:      hasPhotoRaw == 1,
	}, nil
}

func (s *sqliteStore) listArchivedLocationEmployees(ctx context.Context, number string) ([]employee, error) {
	rows, err := s.query(ctx, `
		SELECT time_punch_name, first_name, last_name, department, birthday,
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
		birthday, err := valueAsString(row["birthday"])
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
			FirstName:     firstName,
			LastName:      lastName,
			TimePunchName: timePunchName,
			Department:    normalizeDepartment(department),
			Birthday:      birthday,
			HasPhoto:      hasPhotoRaw == 1,
			ArchivedAt:    time.Unix(archivedAtUnix, 0).UTC().Format(time.RFC3339),
		})
	}
	return employees, nil
}

func (s *sqliteStore) getArchivedLocationEmployee(ctx context.Context, locationNumber, timePunchName string) (*employee, error) {
	rows, err := s.query(ctx, `
		SELECT time_punch_name, first_name, last_name, department, birthday,
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
	birthday, err := valueAsString(rows[0]["birthday"])
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
		FirstName:     firstName,
		LastName:      lastName,
		TimePunchName: tpn,
		Department:    normalizeDepartment(dept),
		Birthday:      birthday,
		HasPhoto:      hasPhotoRaw == 1,
		ArchivedAt:    time.Unix(archivedAtUnix, 0).UTC().Format(time.RFC3339),
	}, nil
}

func (s *sqliteStore) getArchivedEmployeeRecord(ctx context.Context, locationNumber, timePunchName string) (*archivedEmployeeRecord, error) {
	rows, err := s.query(ctx, `
		SELECT id, location_number, time_punch_name, first_name, last_name, department, birthday, profile_image_data, profile_image_mime, archived_at
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
	birthday, err := valueAsString(rows[0]["birthday"])
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
		FirstName:      firstName,
		LastName:       lastName,
		Department:     normalizeDepartment(department),
		Birthday:       birthday,
		ProfileImage:   profileData,
		ProfileMime:    profileMime,
		ArchivedAt:     time.Unix(archivedAtUnix, 0).UTC(),
	}, nil
}

func (s *sqliteStore) archiveAndDeleteLocationEmployee(ctx context.Context, locationNumber, timePunchName string) error {
	rows, err := s.query(ctx, `
		SELECT first_name, last_name, department, birthday, profile_image_data, profile_image_mime
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
	birthday, err := valueAsString(rows[0]["birthday"])
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
			location_number, time_punch_name, first_name, last_name, department, birthday, profile_image_data, profile_image_mime, archived_at
		) VALUES (
			` + sqliteStringLiteral(locationNumber) + `,
			` + sqliteStringLiteral(timePunchName) + `,
			` + sqliteStringLiteral(firstName) + `,
			` + sqliteStringLiteral(lastName) + `,
			` + sqliteStringLiteral(normalizeDepartment(department)) + `,
			` + sqliteStringLiteral(birthday) + `,
			` + sqliteStringLiteral(profileData) + `,
			` + sqliteStringLiteral(profileMime) + `,
			` + strconv.FormatInt(nowUnix, 10) + `
		)
		ON CONFLICT(location_number, time_punch_name)
		DO UPDATE SET
			first_name = excluded.first_name,
			last_name = excluded.last_name,
			department = excluded.department,
			birthday = excluded.birthday,
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
			archived_employee_id, file_data, file_mime, file_name, created_at
		)
		SELECT a.id, d.file_data, d.file_mime, d.file_name, d.created_at
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
	_, err := s.exec(ctx, `
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

func (s *sqliteStore) addEmployeeI9Document(ctx context.Context, locationNumber, timePunchName string, data []byte, mime, fileName string) error {
	encoded := base64.StdEncoding.EncodeToString(data)
	_, err := s.exec(ctx, `
		INSERT INTO employee_i9_documents (location_number, time_punch_name, file_data, file_mime, file_name, created_at)
		VALUES (@location_number, @time_punch_name, @file_data, @file_mime, @file_name, @created_at);
	`, map[string]string{
		"location_number": locationNumber,
		"time_punch_name": timePunchName,
		"file_data":       encoded,
		"file_mime":       mime,
		"file_name":       fileName,
		"created_at":      strconv.FormatInt(time.Now().UTC().Unix(), 10),
	})
	return err
}

func (s *sqliteStore) listEmployeeI9Documents(ctx context.Context, locationNumber, timePunchName string) ([]employeeI9Document, error) {
	rows, err := s.query(ctx, `
		SELECT id, file_name, file_mime, created_at
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
		SELECT id, file_name, file_mime, created_at
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
			ID:        id,
			FileName:  fileName,
			FileMime:  fileMime,
			CreatedAt: time.Unix(createdUnix, 0).UTC(),
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
	_, err := s.exec(ctx, `
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
			location_number, time_punch_name, first_name, last_name, department, birthday
		)
		VALUES (@location_number, @time_punch_name, @first_name, @last_name, @department, @birthday)
		ON CONFLICT(location_number, time_punch_name)
		DO UPDATE SET
			first_name = excluded.first_name,
			last_name = excluded.last_name,
			department = excluded.department,
			birthday = excluded.birthday;
	`, map[string]string{
		"location_number": locationNumber,
		"time_punch_name": emp.TimePunchName,
		"first_name":      emp.FirstName,
		"last_name":       emp.LastName,
		"department":      normalizeDepartment(emp.Department),
		"birthday":        emp.Birthday,
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
			location_number, time_punch_name, punch_date, time_in, time_out, created_at
		)
		VALUES (@location_number, @time_punch_name, @punch_date, @time_in, @time_out, @created_at);
	`, map[string]string{
		"location_number": entry.LocationNum,
		"time_punch_name": entry.TimePunchName,
		"punch_date":      entry.PunchDate,
		"time_in":         entry.TimeIn,
		"time_out":        entry.TimeOut,
		"created_at":      strconv.FormatInt(entry.CreatedAt.UTC().Unix(), 10),
	})
	return err
}

func (s *sqliteStore) listTimePunchEntries(ctx context.Context, locationNumber string) ([]timePunchEntry, error) {
	rows, err := s.query(ctx, `
		SELECT id, location_number, time_punch_name, punch_date, time_in, time_out, created_at
		FROM location_time_punch_entries
		WHERE location_number = @location_number
		ORDER BY created_at DESC;
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
		createdAtUnix, err := valueAsInt64(row["created_at"])
		if err != nil {
			return nil, err
		}
		out = append(out, timePunchEntry{
			ID:            id,
			LocationNum:   locNum,
			TimePunchName: timePunchName,
			PunchDate:     punchDate,
			TimeIn:        timeIn,
			TimeOut:       timeOut,
			CreatedAt:     time.Unix(createdAtUnix, 0).UTC(),
		})
	}
	return out, nil
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

func (s *sqliteStore) createUniformItem(ctx context.Context, item uniformItem, priceCents int64, sizes []string) error {
	nowUnix := strconv.FormatInt(item.CreatedAt.UTC().Unix(), 10)
	parts := []string{
		"BEGIN;",
		`INSERT INTO location_uniform_items (
			location_number, name, price_cents, enabled, image_data, image_mime, created_at, updated_at
		) VALUES (
			` + sqliteStringLiteral(item.LocationNum) + `,
			` + sqliteStringLiteral(item.Name) + `,
			` + strconv.FormatInt(priceCents, 10) + `,
			1,
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
	for idx, size := range sizes {
		parts = append(parts, `INSERT INTO location_uniform_item_sizes (
			item_id, size_label, sort_order, created_at
		) VALUES (
			`+itemIDExpr+`,
			`+sqliteStringLiteral(size)+`,
			`+strconv.Itoa(idx)+`,
			`+nowUnix+`
		) ON CONFLICT(item_id, size_label) DO NOTHING;`)
	}
	parts = append(parts, "COMMIT;")
	_, err := s.exec(ctx, strings.Join(parts, "\n"), nil)
	return err
}

func (s *sqliteStore) listUniformItems(ctx context.Context, locationNumber string, onlyEnabled bool) ([]uniformItem, error) {
	statement := `
		SELECT id, location_number, name, price_cents, enabled, image_data, image_mime, created_at, updated_at
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
		sizes, err := s.listUniformItemSizes(ctx, id)
		if err != nil {
			return nil, err
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
			ImageData:   imageData,
			ImageMime:   imageMime,
			Images:      images,
			Sizes:       sizes,
			CreatedAt:   time.Unix(createdAtUnix, 0).UTC(),
			UpdatedAt:   time.Unix(updatedAtUnix, 0).UTC(),
		})
	}
	return items, nil
}

func (s *sqliteStore) getUniformItemByID(ctx context.Context, locationNumber string, itemID int64) (*uniformItem, error) {
	rows, err := s.query(ctx, `
		SELECT id, location_number, name, price_cents, enabled, image_data, image_mime, created_at, updated_at
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
	sizes, err := s.listUniformItemSizes(ctx, id)
	if err != nil {
		return nil, err
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
		ImageData:   imageData,
		ImageMime:   imageMime,
		Images:      images,
		Sizes:       sizes,
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

func (s *sqliteStore) updateUniformItem(ctx context.Context, locationNumber string, itemID int64, name string, priceCents int64, sizes []string) error {
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
	nowUnix := strconv.FormatInt(time.Now().UTC().Unix(), 10)
	for idx, size := range sizes {
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
			sqliteStringLiteral(line.Size)+", "+
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
			order_id, item_id, item_name, size_option, note, quantity, unit_price_cents, line_total_cents, created_at
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
			size_option,
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
		sizeOption, err := valueAsString(row["size_option"])
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
			SizeOption:  sizeOption,
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
		SELECT id, username, password_hash, is_admin
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

	return &userRecord{
		ID:       id,
		Username: name,
		IsAdmin:  isAdminRaw == 1,
	}, hash, nil
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
		SELECT s.id, s.user_id, s.csrf_token, s.expires_at, u.username, u.is_admin
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

	_, _ = s.exec(ctx, `UPDATE sessions SET last_seen_at = @last_seen_at WHERE id = @id;`, map[string]string{
		"last_seen_at": strconv.FormatInt(time.Now().UTC().Unix(), 10),
		"id":           id,
	})

	return &sessionRecord{ID: sessionID, UserID: userID, CSRFToken: csrfToken, ExpiresAt: expiresAt}, &userRecord{ID: userID, Username: username, IsAdmin: isAdminRaw == 1}, nil
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

	args := []string{s.dbPath, ".timeout 5000"}
	if jsonMode {
		args = append(args, ".mode json")
	}
	args = append(args, "PRAGMA foreign_keys = ON;")
	args = append(args, bindSQLParams(statement, params))

	cmd := exec.CommandContext(runCtx, "sqlite3", args...)
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

func randomToken(bytesLen int) (string, error) {
	buf := make([]byte, bytesLen)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func validateCreateLocation(req createLocationRequest) error {
	name := strings.TrimSpace(req.Name)
	number := strings.TrimSpace(req.Number)
	if name == "" {
		return errors.New("name is required")
	}
	if number == "" {
		return errors.New("number is required")
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
		if item.ItemID <= 0 {
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

func normalizeDepartment(value string) string {
	dept := strings.ToUpper(strings.TrimSpace(value))
	if dept == "" {
		return "INIT"
	}
	if _, ok := allowedDepartments[dept]; ok {
		return dept
	}
	return "INIT"
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
			FirstName:     first,
			LastName:      last,
			TimePunchName: timePunch,
			Terminated:    terminated,
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
		"employee_signature":        "Signature of Employee",
		"employee_signature_date":   "Today's Date mmddyyy",
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

	citizenshipStatus := strings.ToLower(strings.TrimSpace(values.Get("citizenship_status")))
	pdfCheckboxValues := map[string]bool{
		"CB_1": false,
		"CB_2": false,
		"CB_3": false,
		"CB_4": false,
	}
	switch citizenshipStatus {
	case "citizen":
		pdfCheckboxValues["CB_1"] = true
	case "noncitizen_national":
		pdfCheckboxValues["CB_2"] = true
	case "lpr":
		pdfCheckboxValues["CB_3"] = true
	case "alien_authorized":
		pdfCheckboxValues["CB_4"] = true
	}

	if len(pdfTextValues) == 0 && !pdfCheckboxValues["CB_1"] && !pdfCheckboxValues["CB_2"] && !pdfCheckboxValues["CB_3"] && !pdfCheckboxValues["CB_4"] {
		return nil, errors.New("enter at least one i-9 field before saving")
	}
	return fillPDFTemplate("docs/i9.pdf", pdfTextValues, pdfCheckboxValues)
}

func generateFilledW4PDF(values url.Values) ([]byte, error) {
	textFieldMap := map[string]string{
		"first_name_middle":  "topmostSubform[0].Page1[0].Step1a[0].f1_01[0]",
		"last_name":          "topmostSubform[0].Page1[0].Step1a[0].f1_02[0]",
		"address":            "topmostSubform[0].Page1[0].Step1a[0].f1_03[0]",
		"city_state_zip":     "topmostSubform[0].Page1[0].Step1a[0].f1_04[0]",
		"ssn":                "topmostSubform[0].Page1[0].f1_05[0]",
		"dependents_under17": "topmostSubform[0].Page1[0].Step3_ReadOrder[0].f1_06[0]",
		"other_dependents":   "topmostSubform[0].Page1[0].Step3_ReadOrder[0].f1_07[0]",
		"other_income":       "topmostSubform[0].Page1[0].f1_08[0]",
		"deductions":         "topmostSubform[0].Page1[0].f1_09[0]",
		"extra_withholding":  "topmostSubform[0].Page1[0].f1_10[0]",
		"signature":          "topmostSubform[0].Page1[0].f1_12[0]",
		"date":               "topmostSubform[0].Page1[0].f1_13[0]",
		"employer_name_addr": "topmostSubform[0].Page1[0].f1_14[0]",
	}
	pdfTextValues := map[string]string{}
	for formKey, pdfFieldName := range textFieldMap {
		raw := strings.TrimSpace(values.Get(formKey))
		if raw == "" {
			continue
		}
		pdfTextValues[pdfFieldName] = raw
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

func fillPDFTemplate(templatePath string, textValues map[string]string, checkValues map[string]bool) ([]byte, error) {
	if _, err := os.Stat(templatePath); err != nil {
		return nil, errors.New("paperwork template is missing")
	}
	if _, err := exec.LookPath("pdfcpu"); err != nil {
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

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if output, err := exec.CommandContext(ctx, "pdfcpu", "form", "export", templatePath, exportPath).CombinedOutput(); err != nil {
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
			if value, ok := checkValues[name]; ok {
				payload.Forms[formIdx].Checkbox[fieldIdx].Value = value
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
	if output, err := exec.CommandContext(ctx, "pdfcpu", "form", "fill", templatePath, fillPath, outPath).CombinedOutput(); err != nil {
		return nil, fmt.Errorf("unable to fill template: %s", strings.TrimSpace(string(output)))
	}

	pdfData, err := os.ReadFile(outPath)
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
