package service

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"
)

// handleOastCreate handles POST /oast/create
func (s *Server) handleOastCreate(w http.ResponseWriter, r *http.Request) {
	var req OastCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && err != io.EOF {
		s.writeError(w, http.StatusBadRequest, ErrCodeInvalidRequest, "invalid request body", err.Error())
		return
	}

	log.Printf("oast/create: creating new session (label=%q)", req.Label)
	sess, err := s.oastBackend.CreateSession(r.Context(), req.Label)
	if err != nil {
		if IsTimeoutError(err) {
			s.writeError(w, http.StatusGatewayTimeout, ErrCodeTimeout,
				"OAST session creation timed out", err.Error())
		} else if strings.Contains(err.Error(), "already in use") {
			s.writeError(w, http.StatusBadRequest, ErrCodeInvalidRequest,
				"failed to create OAST session", err.Error())
		} else {
			s.writeError(w, http.StatusInternalServerError, ErrCodeBackendError,
				"failed to create OAST session", err.Error())
		}
		return
	}

	log.Printf("oast/create: created session %s with domain %s (label=%q)", sess.ID, sess.Domain, sess.Label)
	resp := OastCreateResponse{
		OastID: sess.ID,
		Domain: sess.Domain,
		Label:  sess.Label,
	}
	s.writeJSON(w, http.StatusOK, resp)
}

// handleOastPoll handles POST /oast/poll
func (s *Server) handleOastPoll(w http.ResponseWriter, r *http.Request) {
	var req OastPollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, ErrCodeInvalidRequest, "invalid request body", err.Error())
		return
	} else if req.OastID == "" {
		s.writeError(w, http.StatusBadRequest, ErrCodeInvalidRequest, "oast_id is required", "")
		return
	}

	// Parse wait duration
	var wait time.Duration
	var err error
	if req.Wait != "" {
		wait, err = time.ParseDuration(req.Wait)
		if err != nil {
			s.writeError(w, http.StatusBadRequest, ErrCodeInvalidRequest, "invalid wait duration", err.Error())
			return
		}
		// Cap at 120 seconds
		if wait > 120*time.Second {
			wait = 120 * time.Second
		}
	}

	log.Printf("oast/poll: polling session %s (wait=%v since=%q limit=%d)", req.OastID, wait, req.Since, req.Limit)
	result, err := s.oastBackend.PollSession(r.Context(), req.OastID, req.Since, wait, req.Limit)
	if err != nil {
		s.writeError(w, http.StatusNotFound, ErrCodeNotFound, "session not found or deleted", err.Error())
		return
	}

	// Convert internal events to API response
	events := make([]OastEvent, len(result.Events))
	for i, e := range result.Events {
		events[i] = OastEvent{
			EventID:   e.ID,
			Time:      e.Time.UTC().Format(time.RFC3339),
			Type:      e.Type,
			SourceIP:  e.SourceIP,
			Subdomain: e.Subdomain,
			Details:   e.Details,
		}
	}

	log.Printf("oast/poll: session %s returned %d events", req.OastID, len(events))
	resp := OastPollResponse{
		Events:       events,
		DroppedCount: result.DroppedCount,
	}
	s.writeJSON(w, http.StatusOK, resp)
}

// handleOastGet handles POST /oast/get
func (s *Server) handleOastGet(w http.ResponseWriter, r *http.Request) {
	var req OastGetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, ErrCodeInvalidRequest, "invalid request body", err.Error())
		return
	} else if req.OastID == "" {
		s.writeError(w, http.StatusBadRequest, ErrCodeInvalidRequest, "oast_id is required", "")
		return
	} else if req.EventID == "" {
		s.writeError(w, http.StatusBadRequest, ErrCodeInvalidRequest, "event_id is required", "")
		return
	}

	log.Printf("oast/get: getting event %s from session %s", req.EventID, req.OastID)
	event, err := s.oastBackend.GetEvent(r.Context(), req.OastID, req.EventID)
	if err != nil {
		s.writeError(w, http.StatusNotFound, ErrCodeNotFound, "session or event not found", err.Error())
		return
	}

	log.Printf("oast/get: returning event %s", req.EventID)
	resp := OastGetResponse{
		EventID:   event.ID,
		Time:      event.Time.UTC().Format(time.RFC3339),
		Type:      event.Type,
		SourceIP:  event.SourceIP,
		Subdomain: event.Subdomain,
		Details:   event.Details,
	}
	s.writeJSON(w, http.StatusOK, resp)
}

// handleOastList handles POST /oast/list
func (s *Server) handleOastList(w http.ResponseWriter, r *http.Request) {
	var req OastListRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && err != io.EOF {
		s.writeError(w, http.StatusBadRequest, ErrCodeInvalidRequest, "invalid request body", err.Error())
		return
	}

	sessions, err := s.oastBackend.ListSessions(r.Context())
	if err != nil {
		if IsTimeoutError(err) {
			s.writeError(w, http.StatusGatewayTimeout, ErrCodeTimeout,
				"OAST session list timed out", err.Error())
		} else {
			s.writeError(w, http.StatusInternalServerError, ErrCodeBackendError,
				"failed to list OAST sessions", err.Error())
		}
		return
	}

	// Sort by creation time descending (most recent first)
	sort.Slice(sessions, func(i, j int) bool {
		return sessions[i].CreatedAt.After(sessions[j].CreatedAt)
	})

	// Apply limit if set
	if req.Limit > 0 && len(sessions) > req.Limit {
		sessions = sessions[:req.Limit]
	}

	// Convert internal sessions to API response
	apiSessions := make([]OastSession, len(sessions))
	for i, sess := range sessions {
		apiSessions[i] = OastSession{
			OastID:    sess.ID,
			Domain:    sess.Domain,
			Label:     sess.Label,
			CreatedAt: sess.CreatedAt.UTC().Format(time.RFC3339),
		}
	}

	log.Printf("oast/list: returning %d active sessions", len(apiSessions))
	resp := OastListResponse{
		Sessions: apiSessions,
	}
	s.writeJSON(w, http.StatusOK, resp)
}

// handleOastDelete handles POST /oast/delete
func (s *Server) handleOastDelete(w http.ResponseWriter, r *http.Request) {
	var req OastDeleteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, ErrCodeInvalidRequest, "invalid request body", err.Error())
		return
	} else if req.OastID == "" {
		s.writeError(w, http.StatusBadRequest, ErrCodeInvalidRequest, "oast_id is required", "")
		return
	}

	log.Printf("oast/delete: deleting session %s", req.OastID)
	if err := s.oastBackend.DeleteSession(r.Context(), req.OastID); err != nil {
		s.writeError(w, http.StatusNotFound, ErrCodeNotFound, "session not found", err.Error())
		return
	}

	s.writeJSON(w, http.StatusOK, OastDeleteResponse{})
}
