package libdnsdnsimple

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/dnsimple/dnsimple-go/dnsimple"
	"github.com/libdns/libdns"
)

// Helper function to convert integer to time.Duration
func toDuration(ttl int) time.Duration {
	return time.Duration(ttl) * time.Second
}

// TODO: Providers must not require additional provisioning steps by the callers; it
// should work simply by populating a struct and calling methods on it. If your DNS
// service requires long-lived state or some extra provisioning step, do it implicitly
// when methods are called; sync.Once can help with this, and/or you can use a
// sync.(RW)Mutex in your Provider struct to synchronize implicit provisioning.

// Provider facilitates DNS record manipulation with <TODO: PROVIDER NAME>.
type Provider struct {
	// TODO: put config fields here (with snake_case json
	// struct tags on exported fields), for example:
	APIToken string `json:"api_token,omitempty"`
}

// GetRecords lists all the records in the zone.
func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	if zone == "" {
		return nil, fmt.Errorf("zone parameter cannot be empty")
	}

	tc := dnsimple.StaticTokenHTTPClient(ctx, p.APIToken)
	client := dnsimple.NewClient(tc)

	// get the current authenticated account
	whoamiResponse, err := client.Identity.Whoami(context.Background())
	if err != nil {
		fmt.Printf("Whoami() returned error: %v\n", err)
		os.Exit(1)
	}

	// Get the account ID
	accountID := strconv.FormatInt(whoamiResponse.Data.Account.ID, 10)

	zoneRecordsResponse, err := client.Zones.ListRecords(ctx, accountID, zone, nil)
	if err != nil {
		return nil, err
	}

	// Convert the DNSimple records to libdns records
	var libdnsRecords []libdns.Record
	for _, record := range zoneRecordsResponse.Data {
		libdnsRecords = append(libdnsRecords, libdns.Record{
			Type:  record.Type,
			Name:  record.Name,
			Value: record.Content,
			TTL:   toDuration(record.TTL),
		})
	}

	return libdnsRecords, nil
}

// AppendRecords adds records to the zone. It returns the records that were added.
func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	if zone == "" {
		return nil, fmt.Errorf("zone parameter cannot be empty")
	}

	tc := dnsimple.StaticTokenHTTPClient(ctx, p.APIToken)
	client := dnsimple.NewClient(tc)

	// get the current authenticated account
	whoamiResponse, err := client.Identity.Whoami(context.Background())
	if err != nil {
		fmt.Printf("Whoami() returned error: %v\n", err)
		os.Exit(1)
	}

	// Get the account ID
	accountID := strconv.FormatInt(whoamiResponse.Data.Account.ID, 10)

	// Append the records to the zone
	var appendedRecords []libdns.Record
	for _, record := range records {
		zoneRecordRequest := dnsimple.ZoneRecordRequest{
			Type:    record.Type,
			Name:    record.Name,
			Content: record.Value,
			TTL:     int(record.TTL.Seconds()),
		}
		zoneRecordResponse, err := client.Zones.CreateRecord(ctx, accountID, zone, zoneRecordRequest)
		if err != nil {
			return appendedRecords, err
		}

		appendedRecord := libdns.Record{
			Type:  zoneRecordResponse.Data.Type,
			Name:  zoneRecordResponse.Data.Name,
			Value: zoneRecordResponse.Data.Content,
			TTL:   toDuration(zoneRecordResponse.Data.TTL),
		}
		appendedRecords = append(appendedRecords, appendedRecord)
	}

	return appendedRecords, nil
}

// SetRecords sets the records in the zone, either by updating existing records or creating new ones.
// It returns the updated records.
func (p *Provider) SetRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	if zone == "" {
		return nil, fmt.Errorf("zone parameter cannot be empty")
	}

	tc := dnsimple.StaticTokenHTTPClient(ctx, p.APIToken)
	client := dnsimple.NewClient(tc)

	// get the current authenticated account
	whoamiResponse, err := client.Identity.Whoami(context.Background())
	if err != nil {
		fmt.Printf("Whoami() returned error: %v\n", err)
		os.Exit(1)
	}

	// Get the account ID
	accountID := strconv.FormatInt(whoamiResponse.Data.Account.ID, 10)

	// Update or create records in the zone
	var updatedRecords []libdns.Record
	for _, record := range records {
		zoneRecordRequest := dnsimple.ZoneRecordRequest{
			Type:    record.Type,
			Name:    record.Name,
			Content: record.Value,
			TTL:     int(record.TTL.Seconds()),
		}
		zoneRecordResponse, err := client.Zones.CreateOrUpdateRecord(ctx, accountID, zone, zoneRecordRequest)
		if err != nil {
			return updatedRecords, err
		}

		updatedRecord := libdns.Record{
			Type:  zoneRecordResponse.Data.Type,
			Name:  zoneRecordResponse.Data.Name,
			Value: zoneRecordResponse.Data.Content,
			TTL:   toDuration(zoneRecordResponse.Data.TTL),
		}
		updatedRecords = append(updatedRecords, updatedRecord)
	}

	return updatedRecords, nil
}

// DeleteRecords deletes the records from the zone. It returns the records that were deleted.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	if zone == "" {
		return nil, fmt.Errorf("zone parameter cannot be empty")
	}

	tc := dnsimple.StaticTokenHTTPClient(ctx, p.APIToken)
	client := dnsimple.NewClient(tc)

	// get the current authenticated account
	whoamiResponse, err := client.Identity.Whoami(context.Background())
	if err != nil {
		fmt.Printf("Whoami() returned error: %v\n", err)
		os.Exit(1)
	}

	// Get the account ID
	accountID := strconv.FormatInt(whoamiResponse.Data.Account.ID, 10)

	// Delete records from the zone
	var deletedRecords []libdns.Record
	for _, record := range records {
		zoneRecordID, err := strconv.Atoi(record.ID)
		if err != nil {
			return deletedRecords, err
		}

		err = client.Zones.DeleteRecord(ctx, accountID, zone, zoneRecordID)
		if err != nil {
			return deletedRecords, err
		}

		deletedRecords = append(deletedRecords, record)
	}

	return deletedRecords, nil
}

// Interface guards
var (
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)
