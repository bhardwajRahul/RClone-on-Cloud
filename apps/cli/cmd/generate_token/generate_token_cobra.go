package generate_token

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var GenerateTokenCmd = &cobra.Command{
	Use:   "generate-token [path/to/private_key] [user_id] [email]",
	Short: "Generate a JWT token for authentication",
	Args:  cobra.ExactArgs(3),
	Run: func(cmd *cobra.Command, args []string) {
		privateKeyPath := args[0]
		userId := args[1]
		email := args[2]
		token, err := GenerateToken(privateKeyPath, userId, email)
		if err != nil {
			fmt.Printf("Error generating token: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(*token)
	},
}
