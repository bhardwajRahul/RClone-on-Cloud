package cmd_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go/modules/mongodb"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	cmd "github.com/ekarton/RClone-Cloud/apps/cli/cmd/migrate"
)

func TestMigrateConfig(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// 1. Start MongoDB testcontainer
	mongodbContainer, err := mongodb.Run(ctx, "mongo:7.0")
	require.NoError(t, err)

	// Clean up the container
	defer func() {
		if err := mongodbContainer.Terminate(ctx); err != nil {
			t.Fatalf("failed to terminate container: %s", err)
		}
	}()

	uri, err := mongodbContainer.ConnectionString(ctx)
	require.NoError(t, err)

	// 2. Setup environment variables
	t.Setenv("MONGODB_URI", uri)

	encryptionKey := make([]byte, 32)
	_, err = rand.Read(encryptionKey)
	require.NoError(t, err)

	keyHex := hex.EncodeToString(encryptionKey)
	t.Setenv("RCLONE_ENCRYPTION_KEY", keyHex)

	// 3. Create a dummy rclone.conf file
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "rclone.conf")

	dummyConfig := `[myremote]
type = s3
provider = AWS
env_auth = false
access_key_id = my_access_key
secret_access_key = my_secret_key
region = us-east-1`

	err = os.WriteFile(configPath, []byte(dummyConfig), 0644)
	require.NoError(t, err)

	// 4. Run the migration
	cmd.Migrate(configPath)

	// 5. Connect to MongoDB and verify the data
	client, err := mongo.Connect(options.Client().ApplyURI(uri))
	require.NoError(t, err)
	defer client.Disconnect(ctx)

	coll := client.Database("rclone").Collection("configs")

	// We expect one document for "myremote"
	var doc bson.M
	err = coll.FindOne(ctx, bson.M{"_id": "myremote"}).Decode(&doc)
	require.NoError(t, err, "could not find 'myremote' config in database")

	// The db document should have a "data" field (the encrypted data) and "_id"
	assert.Contains(t, doc, "data", "expected encrypted 'data' field in mongo document")
}
