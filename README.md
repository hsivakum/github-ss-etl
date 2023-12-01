# Welcome to github ss etl

## This is a etl golang service which will pull secret scanning results from github.

### Please configure the values in the env.example file and create a new file named .env with required values

## How to run the file
1. Make sure the tables are created from the scan-migrate service.
2. run the application using below command
   * ```go build```
   * ```./github-ss-etl``` for linux and ```.\githut-ss-etl``` for windows
   * instead of above 2 commands you can simply do ```go run main.go```


*This script will run and keep the ratelimiting in control and pull data from github then store it to github_scan_results table*