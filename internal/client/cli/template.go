package cli

const textDataTemplate = `
=== Text Data Details ===

Name:    {{.Name}}
ID:      {{.ID}}

Content:
---
{{.Content}}
---
`

const credentialTemplate = `
=== Credential Details ===

Name:     {{.Name}}
ID:       {{.ID}}
Login:    {{.Login}}
Password: {{.Password}}
{{- if .URL }}
URL:      {{.URL}}
{{- end}}
{{- if .Notes }}
Notes:    {{.Notes}}
{{- end}}
`

const binaryDataTemplate = `
=== Binary Data Details ===

Name:     {{.Name}}
ID:       {{.ID}}
{{- if $filename := index .Metadata.CustomFields "filename" }}
Filename: {{$filename}}
{{- end}}
Size:     {{len .Data}} bytes
{{- if .MimeType }}
Type:     {{.MimeType}}
{{- end}}
`

const cardDataTemplate = `
=== Card Data Details ===

Name:   {{.Name}}
ID:     {{.ID}}
Number: {{.Number}}
{{- if .Holder }}
Holder: {{.Holder}}
{{- end}}
{{- if .Expiry }}
Expiry: {{.Expiry}}
{{- end}}
{{- if .CVV }}
CVV:    {{.CVV}}
{{- end}}
{{- if .PIN }}
PIN:    {{.PIN}}
{{- end}}
`
const usageTemplate = `
GophKeeper Client

Usage:
  gophkeeper [OPTIONS] COMMAND

Options:
  --version                    Show version information
  --server URL                 Server URL (default: http://localhost:8080)
  --db PATH                    Path to local database (default: gophkeeper-client.db)
  --master-password PASSWORD   Master password (not recommended, use env var or file)
  --master-password-file PATH  Path to file containing master password

Master Password Priority (highest to lowest):
  1. GOPHKEEPER_MASTER_PASSWORD environment variable
  2. --master-password-file (file path)
  3. --master-password (command line)
  4. Interactive prompt (fallback)

Commands:
  register                Register new user
  login                   Login to server
  logout                  Logout from server
  status                  Show authentication status
  add <type>              Add new data (credential, text, binary, card)
  list <type>             List saved data (credentials, text, binary, cards)
  get <id>                Show full data details
  delete <id>             Delete data (soft delete)
  sync                    Synchronize local data with server

Examples:
  # Interactive password prompt
  gophkeeper register
  gophkeeper login
  gophkeeper list credentials

  # Using environment variable (recommended)
  export GOPHKEEPER_MASTER_PASSWORD='mySecretPassword123'
  gophkeeper sync

  # Using password file (for automation)
  echo 'mySecretPassword123' > ~/.gophkeeper-password
  chmod 600 ~/.gophkeeper-password
  gophkeeper --master-password-file ~/.gophkeeper-password sync

  # Using command line parameter (not recommended)
  gophkeeper --master-password 'mySecretPassword123' add credential

  # Other examples
  gophkeeper add text
  gophkeeper add binary
  gophkeeper add card
  gophkeeper get b692f5c0-2d88-4aa1-a9e1-13aa6e4976d5
  gophkeeper delete b692f5c0-2d88-4aa1-a9e1-13aa6e4976d5
  gophkeeper --server https://example.com login
`

const credentialsListTemplate = `
=== Saved Credentials ===

{{- if eq (len .) 0 }}
No credentials found.

Use 'gophkeeper add credential' to add your first credential.

{{ else }}
Found {{len .}} credential(s):

{{- range . }}
- {{ .Name }}
   ID:    {{ .ID }}
   Login: {{ .Login }}
   {{- if .URL }}
   URL:   {{ .URL }}
   {{- end }}
   {{- if .Notes }}
   Notes: {{ .Notes }}
   {{- end }}

{{- end }}
Note: Passwords are hidden for security. Use 'gophkeeper get <id>' to view full details.
{{- end }}
`

const textDataListTemplate = `
=== Saved Text Data ===

{{- if eq (len .) 0 }}
No text data found.

Use 'gophkeeper add text' to add your first text entry.

{{ else }}
Found {{len .}} text entry(ies):

{{- range . }}
- {{ .Name }}
   ID:      {{ .ID }}
   Preview: {{ if gt (len .Content) 50 }}{{ printf "%.50s..." .Content }}{{ else }}{{ .Content }}{{ end }}

{{- end }}
Use 'gophkeeper get <id>' to view full content.
{{- end }}
`

const binaryDataListTemplate = `
=== Saved Binary Data ===

{{- if eq (len .) 0 }}
No binary data found.

Use 'gophkeeper add binary' to add your first binary file.

{{ else }}
Found {{len .}} binary file(s):

{{- range . }}
- {{ .Name }}
   ID:       {{ .ID }}
   {{- with index .Metadata.CustomFields "filename" }}
   Filename:  {{ . }}
   {{- end }}
   Size:     {{ len .Data }} bytes
   {{- if .MimeType }}
   Type:     {{ .MimeType }}
   {{- end }}

{{- end }}
Use 'gophkeeper get <id>' to download the file.
{{- end }}
`

const cardDataListTemplate = `
=== Saved Card Data ===

{{- if eq (len .) 0 }}
No card data found.

Use 'gophkeeper add card' to add your first card.

{{ else }}
Found {{len .}} card(s):

{{- range . }}
- {{ .Name }}
   ID:     {{ .ID }}
   Number: {{ .Number }}
   {{- if .Holder }}
   Holder:  {{ .Holder }}
   {{- end }}
   {{- if .Expiry }}
   Expiry:  {{ .Expiry }}
   {{- end }}

{{- end }}
Note: Card details are masked. Use 'gophkeeper get <id>' to view full details.
{{- end }}
`
