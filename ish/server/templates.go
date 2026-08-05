package main

import (
	"fmt"
	"net/http"
	"strings"
)

func pageHead(title string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>%s</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: #0d1117; color: #c9d1d9; font-family: 'Segoe UI', system-ui, sans-serif; padding: 20px; max-width: 1200px; margin: 0 auto; }
  h1 { color: #58a6ff; margin-bottom: 16px; font-size: 28px; }
  h2 { color: #79c0ff; margin: 20px 0 10px; font-size: 20px; }
  a { color: #58a6ff; text-decoration: none; }
  a:hover { text-decoration: underline; }
  table { width: 100%%; border-collapse: collapse; margin: 10px 0; }
  th, td { padding: 8px 12px; text-align: left; border-bottom: 1px solid #21262d; }
  th { color: #8b949e; font-size: 12px; text-transform: uppercase; }
  tr:hover { background: #161b22; }
  .btn { display: inline-block; padding: 8px 20px; background: #238636; color: #fff; border: none; border-radius: 6px; cursor: pointer; font-size: 14px; }
  .btn:hover { background: #2ea043; }
  .btn-red { background: #da3633; }
  .btn-red:hover { background: #f85149; }
  .card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px; margin: 10px 0; }
  .tag { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: bold; }
  .tag-red { background: #da363332; color: #f85149; }
  .tag-green { background: #23863632; color: #3fb950; }
  .tag-yellow { background: #d2992232; color: #d29922; }
  .tag-magenta { background: #bc8cff32; color: #bc8cff; }
  .tag-cyan { background: #39c5cf32; color: #39c5cf; }
  input, textarea { background: #0d1117; border: 1px solid #30363d; border-radius: 6px; padding: 8px 12px; color: #c9d1d9; font-size: 14px; width: 100%%; }
  input:focus, textarea:focus { outline: none; border-color: #58a6ff; }
  .search-box { display: flex; gap: 8px; margin-bottom: 20px; }
  .search-box input { flex: 1; }
  .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
  .mono { font-family: 'Cascadia Code', 'Consolas', monospace; font-size: 13px; }
  .muted { color: #8b949e; }
  .danger { color: #f85149; font-weight: bold; }
  .warn { color: #d29922; }
  pre { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 12px; overflow-x: auto; font-size: 13px; }
</style>
</head>
<body>`, title)
}

func pageFooter() string {
	return "\n</body>\n</html>\n"
}

func renderLogin(w http.ResponseWriter, errMsg string) {
	var sb strings.Builder
	sb.WriteString(pageHead("Clover Admin Login"))
	sb.WriteString("<h1>Clover Admin</h1>\n")
	sb.WriteString(`<div class="card" style="max-width:400px;margin:40px auto">
<h2>Login</h2>`)
	if errMsg != "" {
		sb.WriteString(fmt.Sprintf(`<p class="danger">%s</p>`, esc(errMsg)))
	}
	sb.WriteString(`<form method="post" action="/login" style="display:flex;flex-direction:column;gap:12px">
<input type="text" name="username" placeholder="Username" required>
<input type="password" name="password" placeholder="Password" required>
<button type="submit" class="btn">Login</button>
</form>
</div>`)
	sb.WriteString(pageFooter())
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(sb.String()))
}

func renderSetup(w http.ResponseWriter, errMsg string) {
	var sb strings.Builder
	sb.WriteString(pageHead("Clover Initial Setup"))
	sb.WriteString("<h1>Clover Initial Setup</h1>\n")
	sb.WriteString(`<div class="card" style="max-width:400px;margin:40px auto">
<h2>Create Admin Account</h2>
<p class="muted">No admin account exists. Create one to continue.</p>`)
	if errMsg != "" {
		sb.WriteString(fmt.Sprintf(`<p class="danger">%s</p>`, esc(errMsg)))
	}
	sb.WriteString(`<form method="post" action="/setup" style="display:flex;flex-direction:column;gap:12px">
<input type="text" name="username" placeholder="Username" required>
<input type="password" name="password" placeholder="Password (min 12 chars)" required minlength="12">
<input type="password" name="confirm" placeholder="Confirm password" required>
<button type="submit" class="btn">Create Admin</button>
</form>
</div>`)
	sb.WriteString(pageFooter())
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(sb.String()))
}

func renderIndex(w http.ResponseWriter, adminUser string, links []ScanLink, scans []ScanRecord) {
	var sb strings.Builder
	sb.WriteString(pageHead("Clover Scan Dashboard"))
	sb.WriteString(fmt.Sprintf("<h1>Clover Scan Dashboard</h1>\n"))
	sb.WriteString(fmt.Sprintf(`<p class="muted">Logged in as: <span class="mono">%s</span> | <a href="/logout">Logout</a></p>` + "\n", esc(adminUser)))

	// Search bar
	sb.WriteString(`<div class="search-box">
<form action="/search" method="get" style="display:flex;gap:8px;width:100%">
<input type="text" name="q" placeholder="Search by SteamID, account name, HWID, hostname...">
<button type="submit" class="btn">Search</button>
</form>
</div>`)

	// Create link
	sb.WriteString("<h2>Create Scan Link</h2>\n")
	sb.WriteString(`<div class="card">
<form id="linkForm" style="display:flex;flex-direction:column;gap:8px">
<input type="text" id="note" placeholder="Note (player name, team, etc.)">
<input type="text" id="password" placeholder="Player password (to unlock scanner)">
<button type="submit" class="btn">Generate Link</button>
</form>
<div id="linkResult" style="margin-top:10px"></div>
</div>
<script>
document.getElementById('linkForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const note = document.getElementById('note').value;
  const password = document.getElementById('password').value;
  const resp = await fetch('/api/links', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({note, password})});
  const data = await resp.json();
  const url = location.origin + data.url;
  const dlUrl = location.origin + '/dl/' + data.id;
  document.getElementById('linkResult').innerHTML =
    '<p class="mono">Player page: <a href="' + url + '">' + url + '</a></p>' +
    '<p class="mono">Direct download: <a href="' + dlUrl + '">' + dlUrl + '</a></p>' +
    '<p class="muted">The downloaded clover.exe is pre-configured with the player password and your admin token. No command-line flags needed.</p>';
});
</script>`)

	// Links list
	if len(links) > 0 {
		sb.WriteString("<h2>Scan Links</h2>\n<table><tr><th>Link</th><th>Note</th><th>Admin</th><th>Created</th><th>Download</th></tr>\n")
		for _, l := range links {
			sb.WriteString(fmt.Sprintf("<tr><td><a href=\"/s/%s\">/s/%s</a></td><td>%s</td><td class=\"mono\">%s</td><td class=\"muted\">%s</td><td><a href=\"/dl/%s\">clover.exe</a></td></tr>\n",
				esc(l.ID), esc(l.ID), esc(l.Note), esc(l.AdminUser), esc(l.CreatedAt), esc(l.ID)))
		}
		sb.WriteString("</table>\n")
	}

	// Scans list
	if len(scans) > 0 {
		sb.WriteString("<h2>All Scans</h2>\n<table><tr><th>Timestamp</th><th>Admin</th><th>Hostname</th><th>SteamID(s)</th><th>HWID</th><th>Hits</th><th>View</th></tr>\n")
		for _, s := range scans {
			hostname := ""
			hwid := ""
			if s.Hardware != nil {
				hostname = s.Hardware.Hostname
				if len(s.Hardware.HWID) >= 8 {
					hwid = s.Hardware.HWID[:8] + "..."
				}
			}
			steamIDs := ""
			if s.Steam != nil {
				for i, a := range s.Steam.Accounts {
					if i > 0 {
						steamIDs += ", "
					}
					steamIDs += a.SteamID
				}
			}
			hits := len(s.Results) + len(s.DeletedFiles) + len(s.Dirs) + len(s.NamedFiles) + len(s.CS2Conns) + len(s.CS2RWX)
			hitBadge := ""
			if hits > 0 {
				hitBadge = fmt.Sprintf(`<span class="tag tag-red">%d</span>`, hits)
			} else {
				hitBadge = `<span class="tag tag-green">clean</span>`
			}
			sb.WriteString(fmt.Sprintf("<tr><td class=\"muted\">%s</td><td class=\"mono\">%s</td><td>%s</td><td class=\"mono\">%s</td><td class=\"mono muted\">%s</td><td>%s</td><td><a href=\"/view/%s\">view</a></td></tr>\n",
				esc(s.Timestamp), esc(s.AdminUser), esc(hostname), esc(steamIDs), esc(hwid), hitBadge, esc(s.ScanID)))
		}
		sb.WriteString("</table>\n")
	} else {
		sb.WriteString("<p class=\"muted\">No scans yet. Create a link and send it to a player.</p>\n")
	}

	sb.WriteString(pageFooter())
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(sb.String()))
}

func renderScanPage(w http.ResponseWriter, link *ScanLink) {
	var sb strings.Builder
	sb.WriteString(pageHead("Clover Scan"))
	sb.WriteString("<h1>Clover Scan</h1>\n")
	hasPassword := link.PlayerPassword != ""
	sb.WriteString(fmt.Sprintf(`<div class="card">
<h2>Instructions</h2>
<p>1. Download Clover:</p>
<p style="margin:8px 0"><a href="/dl/%s" class="btn">Download clover.exe</a></p>
<p>2. Run <span class="mono">clover.exe</span> as Administrator.</p>`, esc(link.ID)))
	if hasPassword {
		sb.WriteString(`<p>3. When prompted, enter the password given to you by the admin.</p>`)
	} else {
		sb.WriteString(`<p>3. The scan will start automatically.</p>`)
	}
	sb.WriteString(`<p class="muted">Results are sent automatically to the server when the scan completes.</p>
</div>`)
	sb.WriteString(fmt.Sprintf(`<p><a href="/">← Back</a></p>`))
	sb.WriteString(pageFooter())
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(sb.String()))
}

func renderScanDetail(w http.ResponseWriter, rec *ScanRecord) {
	var sb strings.Builder
	sb.WriteString(pageHead("Scan Detail"))
	sb.WriteString("<h1>Scan Detail</h1>\n")
	sb.WriteString(fmt.Sprintf("<p class=\"muted\">%s", esc(rec.Timestamp)))
	if rec.AdminUser != "" {
		sb.WriteString(fmt.Sprintf(" | Checked by: <span class=\"mono danger\">%s</span>", esc(rec.AdminUser)))
	}
	sb.WriteString("</p>\n")
	sb.WriteString("<p><a href=\"/\">← Back to dashboard</a></p>\n")

	// Hardware
	if rec.Hardware != nil {
		hw := rec.Hardware
		sb.WriteString("<h2>Hardware Fingerprint</h2>\n<div class=\"card\">\n")
		sb.WriteString(fmt.Sprintf("<table><tr><th>Hostname</th><td>%s</td></tr>", esc(hw.Hostname)))
		sb.WriteString(fmt.Sprintf("<tr><th>Username</th><td>%s</td></tr>", esc(hw.Username)))
		sb.WriteString(fmt.Sprintf("<tr><th>OS</th><td>%s</td></tr>", esc(hw.OSVersion)))
		sb.WriteString(fmt.Sprintf("<tr><th>MachineGuid</th><td class=\"mono\">%s</td></tr>", esc(hw.MachineGuid)))
		sb.WriteString(fmt.Sprintf("<tr><th>CPU</th><td>%s (ID: %s)</td></tr>", esc(hw.CPUName), esc(hw.CPUID)))
		sb.WriteString(fmt.Sprintf("<tr><th>Board</th><td>%s %s (S/N: %s)</td></tr>", esc(hw.BoardVendor), esc(hw.BoardProduct), esc(hw.BoardSerial)))
		sb.WriteString(fmt.Sprintf("<tr><th>GPU</th><td>%s</td></tr>", esc(hw.GPUName)))
		sb.WriteString(fmt.Sprintf("<tr><th>System S/N</th><td>%s</td></tr>", esc(hw.SystemSerial)))
		for i, d := range hw.Disks {
			sb.WriteString(fmt.Sprintf("<tr><th>Disk %d</th><td>%s S/N: %s %.0fGB</td></tr>", i, esc(d.Model), esc(d.SerialNumber), d.SizeGB))
		}
		sb.WriteString(fmt.Sprintf("<tr><th class=\"danger\">HWID</th><td class=\"mono danger\">%s</td></tr></table>\n", esc(hw.HWID)))
		sb.WriteString("</div>\n")
	}

	// Steam
	if rec.Steam != nil && len(rec.Steam.Accounts) > 0 {
		sb.WriteString("<h2>Steam Accounts</h2>\n<table><tr><th>SteamID</th><th>Account</th><th>Most Recent</th></tr>\n")
		for _, a := range rec.Steam.Accounts {
			mr := ""
			if a.MostRecent {
				mr = "✓"
			}
			sb.WriteString(fmt.Sprintf("<tr><td class=\"mono\">%s</td><td>%s</td><td>%s</td></tr>\n", esc(a.SteamID), esc(a.AccountName), mr))
		}
		sb.WriteString("</table>\n")
		if len(rec.Steam.LibraryPaths) > 0 {
			sb.WriteString("<h3>Library Paths</h3>\n<ul>\n")
			for _, p := range rec.Steam.LibraryPaths {
				sb.WriteString(fmt.Sprintf("<li class=\"mono\">%s</li>\n", esc(p)))
			}
			sb.WriteString("</ul>\n")
		}
	}

	// CS2
	if len(rec.CS2Conns) > 0 {
		sb.WriteString("<h2 class=\"danger\">CS2 Remote Connections</h2>\n<table><tr><th>Remote Address</th><th>Remote Port</th><th>State</th><th>Local</th></tr>\n")
		for _, c := range rec.CS2Conns {
			sb.WriteString(fmt.Sprintf("<tr><td class=\"mono danger\">%s</td><td>%d</td><td>%s</td><td class=\"mono muted\">%s:%d</td></tr>\n",
				esc(c.RemoteAddress), c.RemotePort, esc(c.State), esc(c.LocalAddress), c.LocalPort))
		}
		sb.WriteString("</table>\n")
	}
	if len(rec.CS2RWX) > 0 {
		sb.WriteString("<h2 class=\"danger\">CS2 RWX Memory Regions</h2>\n<table><tr><th>Address</th><th>Size</th><th>Protection</th><th>Type</th></tr>\n")
		for _, r := range rec.CS2RWX {
			sb.WriteString(fmt.Sprintf("<tr><td class=\"mono danger\">0x%x</td><td>%d KB</td><td>%s</td><td>%s</td></tr>\n",
				uint64(r.BaseAddress), uint64(r.RegionSize)/1024, esc(r.Protection), esc(r.RegionType)))
		}
		sb.WriteString("</table>\n")
	}

	// Cheat matches
	if len(rec.Results) > 0 {
		sb.WriteString("<h2 class=\"danger\">Cheat Matches</h2>\n<table><tr><th>Name</th><th>Size</th><th>Matched</th><th>Path</th></tr>\n")
		for _, f := range rec.Results {
			sb.WriteString(fmt.Sprintf("<tr><td>%s</td><td>%.1fMB</td><td class=\"tag tag-red\">%s</td><td class=\"mono muted\">%s</td></tr>\n",
				esc(f.Name), float64(f.Size)/1024/1024, esc(f.Matched), esc(f.Path)))
		}
		sb.WriteString("</table>\n")
	}

	// Deleted files
	if len(rec.DeletedFiles) > 0 {
		sb.WriteString("<h2 class=\"warn\">Deleted Files</h2>\n<table><tr><th>Name</th><th>Path</th><th>Deleted</th></tr>\n")
		for _, f := range rec.DeletedFiles {
			sb.WriteString(fmt.Sprintf("<tr><td>%s</td><td class=\"mono muted\">%s</td><td class=\"muted\">%s</td></tr>\n",
				esc(f.Name), esc(f.Path), esc(f.Deleted.Format("2006-01-02 15:04:05"))))
		}
		sb.WriteString("</table>\n")
	}

	// Target dirs
	if len(rec.Dirs) > 0 {
		sb.WriteString("<h2>Target Directories</h2>\n<table><tr><th>Name</th><th>Path</th><th>Modified</th></tr>\n")
		for _, d := range rec.Dirs {
			sb.WriteString(fmt.Sprintf("<tr><td class=\"tag tag-yellow\">%s</td><td class=\"mono muted\">%s</td><td class=\"muted\">%s</td></tr>\n",
				esc(d.Name), esc(d.Path), esc(d.Modified.Format("2006-01-02 15:04:05"))))
		}
		sb.WriteString("</table>\n")
	}

	// Target files
	if len(rec.NamedFiles) > 0 {
		sb.WriteString("<h2>Target Files</h2>\n<table><tr><th>Name</th><th>Size</th><th>Path</th></tr>\n")
		for _, f := range rec.NamedFiles {
			sb.WriteString(fmt.Sprintf("<tr><td class=\"tag tag-magenta\">%s</td><td>%.1fMB</td><td class=\"mono muted\">%s</td></tr>\n",
				esc(f.Name), float64(f.Size)/1024/1024, esc(f.Path)))
		}
		sb.WriteString("</table>\n")
	}

	// Amcache
	if len(rec.Amcache) > 0 {
		sb.WriteString("<h2>Amcache</h2>\n<table><tr><th>Name</th><th>Path</th><th>Last Run</th></tr>\n")
		for _, a := range rec.Amcache {
			sb.WriteString(fmt.Sprintf("<tr><td class=\"tag tag-magenta\">%s</td><td class=\"mono muted\">%s</td><td class=\"muted\">%s</td></tr>\n",
				esc(a.Name), esc(a.Path), esc(a.LastRun.Format("2006-01-02 15:04:05"))))
		}
		sb.WriteString("</table>\n")
	}

	// Shellbags
	if len(rec.Shellbags) > 0 {
		sb.WriteString("<h2>Shellbags</h2>\n<table><tr><th>Name</th><th>Path</th><th>Last Access</th></tr>\n")
		for _, s := range rec.Shellbags {
			sb.WriteString(fmt.Sprintf("<tr><td class=\"tag tag-cyan\">%s</td><td class=\"mono muted\">%s</td><td class=\"muted\">%s</td></tr>\n",
				esc(s.Name), esc(s.Path), esc(s.LastAccess.Format("2006-01-02 15:04:05"))))
		}
		sb.WriteString("</table>\n")
	}

	// AppData
	if len(rec.AppData) > 0 {
		sb.WriteString("<h2>AppData Roaming</h2>\n<table><tr><th>Name</th><th>Path</th><th>Modified</th></tr>\n")
		for _, a := range rec.AppData {
			sb.WriteString(fmt.Sprintf("<tr><td>%s</td><td class=\"mono muted\">%s</td><td class=\"muted\">%s</td></tr>\n",
				esc(a.FileName), esc(a.FilePath), esc(a.FileModified.Format("2006-01-02 15:04:05"))))
		}
		sb.WriteString("</table>\n")
	}

	totalHits := len(rec.Results) + len(rec.DeletedFiles) + len(rec.CS2Conns) + len(rec.CS2RWX)
	sb.WriteString(fmt.Sprintf("<p class=\"muted\">Scan took %.1fs | Total hits: %d</p>\n", rec.Elapsed, totalHits))
	sb.WriteString(pageFooter())
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(sb.String()))
}

func renderSearch(w http.ResponseWriter, query string, scans []ScanRecord) {
	var sb strings.Builder
	sb.WriteString(pageHead("Search: " + query))
	sb.WriteString("<h1>Search Results</h1>\n")
	sb.WriteString(fmt.Sprintf("<p>Query: <span class=\"mono\">%s</span> — %d results</p>\n", esc(query), len(scans)))
	sb.WriteString("<p><a href=\"/\">← Back to dashboard</a></p>\n")

	if len(scans) > 0 {
		sb.WriteString("<table><tr><th>Timestamp</th><th>Admin</th><th>Hostname</th><th>SteamID(s)</th><th>HWID</th><th>Hits</th><th>View</th></tr>\n")
		for _, s := range scans {
			hostname := ""
			hwid := ""
			if s.Hardware != nil {
				hostname = s.Hardware.Hostname
				if len(s.Hardware.HWID) >= 8 {
					hwid = s.Hardware.HWID[:8] + "..."
				}
			}
			steamIDs := ""
			if s.Steam != nil {
				for i, a := range s.Steam.Accounts {
					if i > 0 {
						steamIDs += ", "
					}
					steamIDs += a.SteamID
				}
			}
			hits := len(s.Results) + len(s.DeletedFiles) + len(s.Dirs) + len(s.NamedFiles) + len(s.CS2Conns) + len(s.CS2RWX)
			hitBadge := ""
			if hits > 0 {
				hitBadge = fmt.Sprintf(`<span class="tag tag-red">%d</span>`, hits)
			} else {
				hitBadge = `<span class="tag tag-green">clean</span>`
			}
			sb.WriteString(fmt.Sprintf("<tr><td class=\"muted\">%s</td><td class=\"mono\">%s</td><td>%s</td><td class=\"mono\">%s</td><td class=\"mono muted\">%s</td><td>%s</td><td><a href=\"/view/%s\">view</a></td></tr>\n",
				esc(s.Timestamp), esc(s.AdminUser), esc(hostname), esc(steamIDs), esc(hwid), hitBadge, esc(s.ScanID)))
		}
		sb.WriteString("</table>\n")
	} else {
		sb.WriteString("<p class=\"muted\">No scans found matching this query.</p>\n")
	}

	sb.WriteString(pageFooter())
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(sb.String()))
}
