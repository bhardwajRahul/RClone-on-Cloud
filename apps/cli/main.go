package main

import (
	"fmt"
	"os"

	generate_token_cmd "github.com/ekarton/RClone-Cloud/apps/cli/cmd/generate_token"
	migrate_cmd "github.com/ekarton/RClone-Cloud/apps/cli/cmd/migrate"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run . <command> [arguments]")
		fmt.Println("\nCommands:")
		fmt.Println("  migrate <path/to/rclone.conf>   Migrate an existing rclone.conf to MongoDB")
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "migrate":
		if len(os.Args) < 3 {
			fmt.Println("Usage: go run . migrate <path/to/rclone.conf>")
			os.Exit(1)
		}
		configPath := os.Args[2]
		migrate_cmd.Migrate(configPath)
	case "generate-token":
		if len(os.Args) < 4 {
			fmt.Println("Usage: go run . generate-token <path/to/private_key> <user_id> <email>")
			os.Exit(1)
		}
		privateKeyPath := os.Args[2]
		userId := os.Args[3]
		email := os.Args[4]
		token, err := generate_token_cmd.GenerateToken(privateKeyPath, userId, email)
		if err != nil {
			fmt.Printf("Error generating token: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(*token)
	default:
		fmt.Printf("Unknown command: %s\n", command)
		os.Exit(1)
	}
}
