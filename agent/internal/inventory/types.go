// Package inventory collects hardware and software facts from the local machine.
// The JSON shape matches the server's InventorySchema (server/src/inventory/schema.ts).
package inventory

import "time"

type Inventory struct {
	CollectedAt   time.Time   `json:"collectedAt"`
	Hardware      Hardware    `json:"hardware"`
	OS            OSInfo      `json:"os"`
	Disks         []Disk      `json:"disks"`
	Network       []NetIf     `json:"network"`
	Software      []Software  `json:"software"`
	Patches       []Patch     `json:"patches"`
	Services      []Service   `json:"services"`
	Autostart     []Autostart `json:"autostart"`
	LocalUsers    []User      `json:"localUsers"`
	LocalGroups   []Group     `json:"localGroups"`
	LoggedOnUsers []string    `json:"loggedOnUsers"`
	// Security is the security posture (disk encryption, antivirus, firewall, …); nil if not collected.
	Security *Security `json:"security,omitempty"`
}

// Security posture (server: SecuritySchema in server/src/inventory/schema.ts).
type Security struct {
	Encryption Encryption  `json:"encryption"`
	Antivirus  []Antivirus `json:"antivirus"`
	Firewall   Firewall    `json:"firewall"`
	SecureBoot *bool       `json:"secureBoot"`
	TPM        TPM         `json:"tpm"`
}

type Encryption struct {
	Product *string  `json:"product"`
	Volumes []Volume `json:"volumes"`
}

type Volume struct {
	Volume    string  `json:"volume"`
	System    *bool   `json:"system"`
	Encrypted *bool   `json:"encrypted"`
	Status    *string `json:"status"`
	Method    *string `json:"method"`
	// Protection false = BitLocker suspended (key stored in clear)
	Protection *bool `json:"protection"`
}

type Antivirus struct {
	Name               string  `json:"name"`
	Enabled            *bool   `json:"enabled"`
	Realtime           *bool   `json:"realtime"`
	UpToDate           *bool   `json:"upToDate"`
	SignatureVersion   *string `json:"signatureVersion"`
	SignatureUpdatedAt *string `json:"signatureUpdatedAt"`
	LastScanAt         *string `json:"lastScanAt"`
}

type Firewall struct {
	Product  *string           `json:"product"`
	Enabled  *bool             `json:"enabled"`
	Profiles []FirewallProfile `json:"profiles"`
}

type FirewallProfile struct {
	Name    string `json:"name"`
	Enabled *bool  `json:"enabled"`
}

type TPM struct {
	Present *bool   `json:"present"`
	Ready   *bool   `json:"ready"`
	Version *string `json:"version"`
}

func (s *Security) normalize() {
	if s.Encryption.Volumes == nil {
		s.Encryption.Volumes = []Volume{}
	}
	if s.Antivirus == nil {
		s.Antivirus = []Antivirus{}
	}
	if s.Firewall.Profiles == nil {
		s.Firewall.Profiles = []FirewallProfile{}
	}
}

type Hardware struct {
	Manufacturer *string  `json:"manufacturer"`
	Model        *string  `json:"model"`
	SerialNumber *string  `json:"serialNumber"`
	Chassis      *string  `json:"chassis"`
	BiosVendor   *string  `json:"biosVendor"`
	BiosVersion  *string  `json:"biosVersion"`
	BiosDate     *string  `json:"biosDate"`
	CPU          CPU      `json:"cpu"`
	MemoryBytes  *float64 `json:"memoryBytes"`
}

type CPU struct {
	Model             *string  `json:"model"`
	Cores             *float64 `json:"cores"`
	LogicalProcessors *float64 `json:"logicalProcessors"`
	MHz               *float64 `json:"mhz"`
}

type OSInfo struct {
	Name        *string `json:"name"`
	Version     *string `json:"version"`
	Build       *string `json:"build"`
	Arch        *string `json:"arch"`
	Kernel      *string `json:"kernel"`
	InstallDate *string `json:"installDate"`
	LastBoot    *string `json:"lastBoot"`
	// DistroID is the Linux os-release ID (debian, ubuntu, rocky, …) – used for OSV.
	DistroID *string `json:"distroId,omitempty"`
}

type Disk struct {
	Name      string   `json:"name"`
	Mount     *string  `json:"mount"`
	FSType    *string  `json:"fsType"`
	SizeBytes *float64 `json:"sizeBytes"`
	FreeBytes *float64 `json:"freeBytes"`
}

type NetIf struct {
	Name string   `json:"name"`
	MAC  *string  `json:"mac"`
	Up   bool     `json:"up"`
	IPv4 []string `json:"ipv4"`
	IPv6 []string `json:"ipv6"`
}

type Software struct {
	Name        string  `json:"name"`
	Version     string  `json:"version"`
	Publisher   string  `json:"publisher"`
	InstallDate *string `json:"installDate"`
	Source      string  `json:"source"`
	Arch        string  `json:"arch"`
	// dpkg: source package + version; rpm: source RPM name + epoch:version-release (OSV)
	SourceName    *string `json:"sourceName,omitempty"`
	SourceVersion *string `json:"sourceVersion,omitempty"`
}

type Patch struct {
	ID          string  `json:"id"`
	Description *string `json:"description"`
	InstalledOn *string `json:"installedOn"`
}

type Service struct {
	Name        string  `json:"name"`
	DisplayName *string `json:"displayName"`
	State       *string `json:"state"`
	StartMode   *string `json:"startMode"`
}

type Autostart struct {
	Name     string  `json:"name"`
	Command  *string `json:"command"`
	Location *string `json:"location"`
}

type User struct {
	Name     string  `json:"name"`
	FullName *string `json:"fullName"`
	Disabled *bool   `json:"disabled"`
	UID      *string `json:"uid"`
}

type Group struct {
	Name    string   `json:"name"`
	Members []string `json:"members"`
}

// ptr helpers
func sp(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func fp(f float64) *float64 {
	if f == 0 {
		return nil
	}
	return &f
}

func bp(b bool) *bool { return &b }

// normalize replaces nil slices by empty ones so the JSON contains [] instead of null.
func (inv *Inventory) normalize() {
	if inv.Disks == nil {
		inv.Disks = []Disk{}
	}
	if inv.Network == nil {
		inv.Network = []NetIf{}
	}
	if inv.Software == nil {
		inv.Software = []Software{}
	}
	if inv.Patches == nil {
		inv.Patches = []Patch{}
	}
	if inv.Services == nil {
		inv.Services = []Service{}
	}
	if inv.Autostart == nil {
		inv.Autostart = []Autostart{}
	}
	if inv.LocalUsers == nil {
		inv.LocalUsers = []User{}
	}
	if inv.LocalGroups == nil {
		inv.LocalGroups = []Group{}
	}
	if inv.LoggedOnUsers == nil {
		inv.LoggedOnUsers = []string{}
	}
	for i := range inv.Network {
		if inv.Network[i].IPv4 == nil {
			inv.Network[i].IPv4 = []string{}
		}
		if inv.Network[i].IPv6 == nil {
			inv.Network[i].IPv6 = []string{}
		}
	}
	for i := range inv.LocalGroups {
		if inv.LocalGroups[i].Members == nil {
			inv.LocalGroups[i].Members = []string{}
		}
	}
	if inv.Security != nil {
		inv.Security.normalize()
	}
}
