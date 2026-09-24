  ### Cách chạy
  Tạo VMware Snapshot, mở PowerShell bằng đúng tài khoản cần áp dụng user policy và chọn Run as Administrator:
  
  Set-Location 'C:\Lab\HardeningKitty'

  powershell.exe `
      -NoProfile `
      -ExecutionPolicy Bypass `
      -File '.\01-Win11-HardeningKitty-Before-Hardening.ps1'

  Nếu đã tạo snapshot và xác nhận đúng tài khoản:

  powershell.exe `
      -NoProfile `
      -ExecutionPolicy Bypass `
      -File '.\01-Win11-HardeningKitty-Before-Hardening.ps1' `
      -SnapshotCreated `
      -CurrentUserConfirmed

  Script mặc định yêu cầu Windows 11 25H2 build 26200 và tự reboot sau khi HailMary hoàn tất.

  ### Nếu chỉ cần Hardening không cần audit chuyên sâu lại thì đến bước này đã xong, cần audit sâu hơn thì làm tiếp các bước dưới đây

  Sau reboot, đăng nhập bằng cùng tài khoản rồi chạy:

  Set-Location 'C:\Lab\HardeningKitty'

  powershell.exe `
      -NoProfile `
      -ExecutionPolicy Bypass `
      -File '.\02-Win11-HardeningKitty-Audit-After.ps1'

  ### Thứ tự sáu finding list

  finding_list_0x6d69636b_machine.csv
  finding_list_0x6d69636b_user.csv

  finding_list_msft_security_baseline_windows_11_25h2_machine.csv
  finding_list_msft_security_baseline_windows_11_25h2_user.csv

  finding_list_cis_microsoft_windows_11_enterprise_24h2_machine.csv
  finding_list_cis_microsoft_windows_11_enterprise_24h2_user.csv

  CIS được chạy cuối để giá trị CIS được ưu tiên khi nhiều baseline cấu hình cùng một policy.

  ### Dữ liệu đầu ra

  C:\HKLab\Reports_Before
  C:\HKLab\Reports_Hardening
  C:\HKLab\Reports_After
  C:\HKLab\Backup
  C:\HKLab\HardeningKitty-Win11-State.json

  Lưu ý:

  - Hai list CIS là cho Windows 11 Enterprise 24H2, trong khi máy là Windows 11 Pro 25H2. Một số policy có thể không tồn
    tại hoặc cho kết quả khác.

  - Sáu list có nhiều policy trùng nhau. Giá trị cuối cùng phụ thuộc thứ tự áp dụng.
  - Các *_user.csv tác động vào HKCU của tài khoản đang chạy PowerShell.
  - File AFTER sẽ từ chối chạy nếu máy, build hoặc tài khoản khác với lần chạy đầu.
  - Nếu cần chạy trên build khác, có thể thêm -AllowVersionMismatch, nhưng chỉ nên làm sau khi kiểm tra tính tương thích
    của finding list.
