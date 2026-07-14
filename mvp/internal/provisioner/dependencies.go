package provisioner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type dependencyClient struct {
	baseURL    string
	httpClient *http.Client
}

func newDependencyClient(baseURL string) *dependencyClient {
	return &dependencyClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		httpClient: &http.Client{
			Timeout: 3 * time.Second,
		},
	}
}

func (client *dependencyClient) validateReservation(ctx context.Context, reservationID string) (Reservation, error) {
	var reservation Reservation
	path := "/mock/v1/scheduler/reservations/" + url.PathEscape(reservationID)
	if err := client.getJSON(ctx, path, &reservation); err != nil {
		return Reservation{}, fmt.Errorf("validate scheduler reservation: %w", err)
	}
	if !reservation.Valid {
		return Reservation{}, errors.New("scheduler reservation is invalid")
	}
	return reservation, nil
}

func (client *dependencyClient) resolveChallenge(ctx context.Context, challengeID string) (Challenge, error) {
	var challenge Challenge
	path := "/mock/v1/catalog/challenges/" + url.PathEscape(challengeID)
	if err := client.getJSON(ctx, path, &challenge); err != nil {
		return Challenge{}, fmt.Errorf("resolve challenge catalog entry: %w", err)
	}
	return challenge, nil
}

func (client *dependencyClient) verifyEndpoint(ctx context.Context, endpoint string) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return errors.New("build endpoint verification request")
	}

	response, err := client.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("verify endpoint: %w", err)
	}
	defer response.Body.Close()

	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("endpoint returned HTTP %d", response.StatusCode)
	}

	return nil
}

func (client *dependencyClient) releaseReservation(ctx context.Context, reservationID string, instanceID string) error {
	payload := map[string]string{
		"reservationId": reservationID,
		"instanceId":    instanceID,
	}
	return client.postJSON(ctx, "/mock/v1/scheduler/releases", payload)
}

func (client *dependencyClient) publishEvent(ctx context.Context, target string, eventName string, instance Instance) error {
	payload := map[string]any{
		"event":       eventName,
		"instanceId":  instance.InstanceID,
		"teamId":      instance.TeamID,
		"challengeId": instance.ChallengeID,
		"phase":       instance.Phase,
		"endpoint":    instance.Endpoint,
		"expiresAt":   instance.ExpiresAt,
	}
	return client.postJSON(ctx, target, payload)
}

func (client *dependencyClient) getJSON(ctx context.Context, path string, destination any) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, client.baseURL+path, nil)
	if err != nil {
		return errors.New("build dependency request")
	}

	response, err := client.httpClient.Do(request)
	if err != nil {
		return errors.New("dependency is unavailable")
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return fmt.Errorf("dependency returned HTTP %d", response.StatusCode)
	}

	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(destination); err != nil {
		return errors.New("decode dependency response")
	}

	return nil
}

func (client *dependencyClient) postJSON(ctx context.Context, path string, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return errors.New("encode dependency request")
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, client.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return errors.New("build dependency request")
	}
	request.Header.Set("Content-Type", "application/json")

	response, err := client.httpClient.Do(request)
	if err != nil {
		return errors.New("dependency is unavailable")
	}
	defer response.Body.Close()

	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("dependency returned HTTP %d", response.StatusCode)
	}

	return nil
}
