package pkg

import (
	"fmt"
	"os"
	"path"
	"time"
)

func LogToFile(filename string, data []byte) error {
	file, err := os.OpenFile(path.Join("logs", filename), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0755)
	if err != nil {
		return fmt.Errorf("error opening file: %w", err)
	}
	defer file.Close()

	logEntry := fmt.Sprintf("%s %s\n", time.Now().Format(time.RFC3339), string(data))

	if _, err := file.WriteString(logEntry); err != nil {
		return fmt.Errorf("failed to write to file: %w", err)
	}
	return nil
}
