package main

import (
	"context"
	"fmt"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/google/go-github/v56/github"
	"github.com/jmoiron/sqlx"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"golang.org/x/oauth2"
	"log"
	"net/url"
	"os"
	"strings"
	"time"
)

var (
	repos = []string{
		"https://github.com/shahidmd27/sendinbluev2secrets.git",
		"https://github.com/shahidmd27/razorpaysecrets.git",
		"https://github.com/shahidmd27/pulumisecrets.git",
		"https://github.com/shahidmd27/postmansecrets.git",
		"https://github.com/shahidmd27/optimizelysecrets.git",
		"https://github.com/shahidmd27/npmtokenv2secrets.git",
		"https://github.com/shahidmd27/discordwebhooksecrets.git",
		"https://github.com/shahidmd27/datadogsecrets.git",
		"https://github.com/shahidmd27/confluentsecrets.git",
		"https://github.com/shahidmd27/coinbasesecrets.git",
		"https://github.com/shahidmd27/coinapisecrets.git",
		"https://github.com/shahidmd27/circlecisecrets.git",
		"https://github.com/shahidmd27/accuweathersecrets.git",
		"https://github.com/shahidmd27/ahasecrets.git",
		"https://github.com/shahidmd27/airshipsecrets.git",
		"https://github.com/shahidmd27/alchemysecrets.git",
		"https://github.com/shahidmd27/netlifysecrets.git",
		"https://github.com/shahidmd27/nitrosecrets.git",
		"https://github.com/shahidmd27/newrelicpersonalapikeysecrets.git",
		"https://github.com/shahidmd27/scalewaykeysecrets.git",
		"https://github.com/shahidmd27/oktasecrets.git",
		"https://github.com/shahidmd27/npmtokensecrets.git",
		"https://github.com/shahidmd27/metaapisecrets.git",
		"https://github.com/shahidmd27/ftpsecrets.git",
		"https://github.com/shahidmd27/discordbottokensecrets.git",
		"https://github.com/shahidmd27/mirosecrets.git",
		"https://github.com/shahidmd27/ldapsecrets.git",
		"https://github.com/shahidmd27/ibmclouduserkeysecrets.git",
		"https://github.com/shahidmd27/databrickstokensecrets.git",
		"https://github.com/shahidmd27/couchbasesecrets.git",
		"https://github.com/shahidmd27/awssessionkeyssecrets.git",
		"https://github.com/shahidmd27/alibabasecrets.git",
		"https://github.com/shahidmd27/nasdaqdatalinksecrets.git",
		"https://github.com/shahidmd27/onedesksecrets.git",
		"https://github.com/shahidmd27/paystacksecrets.git",
		"https://github.com/shahidmd27/rabbitmqsecrets.git",
		"https://github.com/shahidmd27/sumologickeysecrets.git",
		"https://github.com/shahidmd27/redissecrets.git",
		"https://github.com/aaronjtom/awsSecrets",
		"https://github.com/aaronjtom/azurebatchSecrets",
		"https://github.com/aaronjtom/snowflakeSecrets",
		"https://github.com/aaronjtom/twitchSecrets",
		"https://github.com/aaronjtom/webexSecrets",
		"https://github.com/aaronjtom/yelpSecrets",
		"https://github.com/aaronjtom/youtubeapikeySecrets",
		"https://github.com/aaronjtom/zendeskapiSecrets",
		"https://github.com/aaronjtom/zeplinSecrets",
		"https://github.com/aaronjtom/mongodbSecrets", // unicode issue
		"https://github.com/aaronjtom/jiratoken_v2Secrets",
		"https://github.com/aaronjtom/jiratokenSecrets",
		"https://github.com/aaronjtom/figmapersonalaccesstokenSecrets",
		"https://github.com/aaronjtom/facebookauthSecrets",
		"https://github.com/aaronjtom/hiveSecrets",
		"https://github.com/aaronjtom/herokuSecrets",
		"https://github.com/aaronjtom/gitlabv2Secrets",
		"https://github.com/aaronjtom/gitlabSecrets",
		"https://github.com/aaronjtom/githubappSecrets",
		"https://github.com/aaronjtom/github_oauth2Secrets",
		"https://github.com/aaronjtom/githubSecrets",
		"https://github.com/aaronjtom/flickrSecrets",
		"https://github.com/aaronjtom/cloudflareglobalapikeySecrets",
		"https://github.com/aaronjtom/cloudflarecakeySecrets",
		"https://github.com/aaronjtom/cloudflareapitokenSecrets",
		"https://github.com/aaronjtom/salesforcesecrets",
		"https://github.com/aaronjtom/revsecrets",
		"https://github.com/aaronjtom/gcpsecrets",
		"https://github.com/aaronjtom/AgoraSecrets",
		"https://github.com/shahidmd27/sentrytokens",
		"https://github.com/shahidmd27/helpcrunchsecrets",
		"https://github.com/shahidmd27/spotifysecrets",
		"https://github.com/shahidmd27/sourcegraphsecrets",
		"https://github.com/shahidmd27/snowflakesecrets",
		"https://github.com/shahidmd27/grafanasecrets",
		"https://github.com/shahidmd27/githubsecrets",
		"https://github.com/shahidmd27/grafanaservices",
		"https://github.com/shahidmd27/crunchbasetokens",
	}
)

type ScannedResults struct {
	Number                int64      `db:"id"`
	RepoURL               string     `db:"repo_url"`
	State                 string     `db:"state"`
	FoundAt               time.Time  `db:"found_at"`
	Path                  string     `db:"path"`
	CommitSHA             string     `db:"commit_sha"`
	SecretType            string     `db:"secret_type"`
	SecretTypeDisplayName string     `db:"secret_type_display_name"`
	Raw                   string     `db:"raw"`
	CreatedAt             time.Time  `db:"created_at"`
	ModifiedAt            *time.Time `db:"modified_at"`
	DeletedAt             *time.Time `db:"deleted_at"`
}

func init() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal(err)
	}
}
func main() {

	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		panic(err)
	}

	keyVaultURL := os.Getenv("KEY_VAULT_URL")

	secretClient, err := azsecrets.NewClient(keyVaultURL, cred, nil)
	if err != nil {
		panic(err)
	}

	githubAPIToken, err := secretClient.GetSecret(context.TODO(), "SS-TOKEN", "", nil)
	if err != nil {
		panic(err)
	}

	dbPassword, err := secretClient.GetSecret(context.TODO(), "DB-PASSWORD", "", nil)
	if err != nil {
		panic(err)
	}

	// GitHub client setup
	ctx := context.Background()
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: *githubAPIToken.Value},
	)
	tc := oauth2.NewClient(ctx, ts)
	client := github.NewClient(tc)

	// PostgreSQL connection details
	dbInfo := url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword(os.Getenv("DB_USER"), *dbPassword.Value),
		Host:     fmt.Sprintf("%s:%s", os.Getenv("DB_HOST"), os.Getenv("DB_PORT")),
		Path:     os.Getenv("DB_NAME"),
		RawQuery: "sslmode=disable",
	}

	// Database setup
	db, err := sqlx.Connect("postgres", dbInfo.String())
	if err != nil {
		log.Fatal(err)
	}

	// Iterate over repositories
	for _, repoURL := range repos {
		owner, repoName := extractOwnerAndRepo(repoURL)

		// Fetch all pages of alerts
		var allAlerts []*github.SecretScanningAlert
		var remainingRequests int
		var resetTimestamp time.Time
		page := 1
		for {
			// Fetch alerts
			alerts, resp, err := client.SecretScanning.ListAlertsForRepo(ctx, owner, repoName, &github.SecretScanningAlertListOptions{
				ListOptions: github.ListOptions{
					Page:    page,
					PerPage: 100,
				},
			})
			if err != nil {
				log.Fatal(err)
			}

			// Extract rate limit information from the response
			rate := resp.Rate
			remainingRequests = rate.Remaining
			resetTimestamp = rate.Reset.Time
			// Check if remaining requests are below a certain threshold
			if remainingRequests < 10 {
				// Calculate the wait duration until the next reset time plus a buffer (2 minutes)
				waitDuration := resetTimestamp.Sub(time.Now()) + 2*time.Minute
				log.Printf("Rate limit exceeded. Sleeping for %v until reset time: %v", waitDuration, resetTimestamp)
				time.Sleep(waitDuration)
			}

			allAlerts = append(allAlerts, alerts...)

			// Check if there are more pages to fetch
			if resp.NextPage == 0 {
				break
			}
			page = resp.NextPage
		}

		// Process the alerts and accumulate data
		var scannedResults []ScannedResults
		for _, alert := range allAlerts {
			scannedResult := ScannedResults{
				Number:                int64(*alert.Number),
				RepoURL:               repoURL,
				State:                 alert.GetState(),
				FoundAt:               alert.GetCreatedAt().Time,
				Path:                  "file.txt", // Set the path
				CommitSHA:             "",
				SecretType:            alert.GetSecretType(),            // Set the secret type
				SecretTypeDisplayName: alert.GetSecretTypeDisplayName(), // Set the secret type display name
				Raw:                   alert.GetSecret(),                // Set your redacted secret logic here
			}
			scannedResults = append(scannedResults, scannedResult)
		}

		err := insertScanResults(db, scannedResults)
		if err != nil {
			log.Fatal(err)
		}
	}

	// Close the database connection
	if err := db.Close(); err != nil {
		log.Fatal(err)
	}
}

func insertScanResults(db *sqlx.DB, results []ScannedResults) error {
	// Prepare the query template
	query := `INSERT INTO github_scan_results (
					number,
					file,
					url,
					commit_sha,
					raw,
					detector_name,
					detector_display_name,
					found_at
				) VALUES %s ON CONFLICT DO NOTHING;`

	// Define the maximum number of parameters supported by PostgreSQL
	maxParams := int64(65535)

	// Calculate the batch size based on the number of columns and maxParams
	columnsPerRow := int64(8)
	batchSize := maxParams / columnsPerRow

	// Create a slice to hold the values for multiple rows
	var values []interface{}

	var count int64 = 0
	// Create a slice to hold the value placeholders for a single row
	valuePlaceholders := make([]string, 0, int64(len(results))*columnsPerRow)
	for _, result := range results {
		valuePlaceholders = append(valuePlaceholders,
			fmt.Sprintf("($%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d)",
				(count*columnsPerRow)+1, (count*columnsPerRow)+2, (count*columnsPerRow)+3,
				(count*columnsPerRow)+4, (count*columnsPerRow)+5, (count*columnsPerRow)+6,
				(count*columnsPerRow)+7, (count*columnsPerRow)+8))

		values = append(values,
			result.Number, result.Path, result.RepoURL, result.CommitSHA, result.Raw, result.SecretType,
			result.SecretTypeDisplayName, result.FoundAt,
		)

		// If we reach the batch size or the end of the results, execute the query
		if (count+1)%batchSize == 0 || count == int64(len(results))-1 {
			valuesBinding := strings.Join(valuePlaceholders, ",")
			execQuery := fmt.Sprintf(query, valuesBinding)

			// Execute the query
			_, err := db.Exec(execQuery, values...)
			if err != nil {
				log.Println("Error inserting into database:", err)
				return err
			}

			// Reset values and placeholders for the next batch
			values = nil
			count = 0
			valuePlaceholders = nil
			continue
		}

		count++
	}

	return nil
}

func extractOwnerAndRepo(repoURL string) (string, string) {
	parts := strings.Split(repoURL, "/")
	if len(parts) < 4 {
		log.Fatalf("Invalid repository URL format: %s", repoURL)
	}
	owner := parts[3]
	repoName := strings.TrimSuffix(parts[4], ".git")
	return owner, repoName
}
