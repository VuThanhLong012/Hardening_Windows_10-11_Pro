  ### Cách chạy
  Khi tải file zip về và giải nén => Đổi tên Folder thành Lab => Folder con thành HardeningKitty => Move Folder Lab sang C:\
  Tạo Snapshot, sau đó mở PowerShell bằng đúng tài khoản cần áp dụng user policy và chọn Run as Administrator:

  Set-Location 'C:\Lab\HardeningKitty'

  powershell.exe `
      -NoProfile `
      -ExecutionPolicy Bypass `
      -File '.\01-Win10-HardeningKitty-Before-Hardening.ps1'
	  
  Script sẽ yêu cầu xác nhận:

  - Đã tạo VMware Snapshot.
  - Tài khoản hiện tại chính là tài khoản cần áp dụng các *_user.csv.

  Nếu muốn bỏ qua hai câu hỏi vì đã kiểm tra trước:

  powershell.exe `
      -NoProfile `
      -ExecutionPolicy Bypass `
      -File '.\01-Win10-HardeningKitty-Before-Hardening.ps1' `
      -SnapshotCreated `
      -CurrentUserConfirmed

  Script mặc định sẽ tự reboot sau khi HailMary hoàn tất.

  ### Nếu chỉ cần Hardening không cần audit chuyên sâu lại thì đến bước này đã xong, cần audit sâu hơn thì làm tiếp các bước dưới đây

  Sau khi Windows khởi động lại, đăng nhập bằng cùng tài khoản và chạy:
  Set-Location 'C:\Lab\HardeningKitty'

  powershell.exe `
      -NoProfile `
      -ExecutionPolicy Bypass `
      -File '.\02-Win10-HardeningKitty-Audit-After.ps1'

  ### Finding list mặc định

  Script sử dụng bốn list phù hợp nhất với Windows 10 22H2:

  finding_list_msft_security_baseline_windows_10_22h2_machine.csv
  finding_list_msft_security_baseline_windows_10_22h2_user.csv
  finding_list_cis_microsoft_windows_10_enterprise_22h2_3.0.0_machine.csv
  finding_list_cis_microsoft_windows_10_enterprise_22h2_3.0.0_user.csv

  Microsoft Baseline được áp dụng trước, CIS áp dụng sau để giá trị CIS được ưu tiên nếu hai baseline xung đột.

  Hai list sau không được chạy mặc định:

  finding_list_0x6d69636b_machine.csv
  finding_list_0x6d69636b_user.csv
  Theo README của HardeningKitty, chúng hiện dành cho Windows 11 25H2, không phải Windows 10. Nếu vẫn muốn chạy đúng sáu
  list ban đầu:

  powershell.exe `
      -NoProfile `
      -ExecutionPolicy Bypass `
      -File '.\01-Win10-HardeningKitty-Before-Hardening.ps1' `
      -SnapshotCreated `
      -CurrentUserConfirmed `
      -IncludeIncompatible0xLists

  Sau đó nhập:

  INCLUDE-0X

  File thứ hai sẽ tự nhớ và audit lại đúng sáu list, không cần thêm switch.

  ### Dữ liệu đầu ra

  C:\HKLab\Reports_Before
  C:\HKLab\Reports_Hardening
  C:\HKLab\Reports_After
  C:\HKLab\Backup
  C:\HKLab\HardeningKitty-Win10-State.json
  
  File state lưu tên máy, build Windows, tài khoản, thư mục và danh sách CSV đã chạy. Audit AFTER sẽ dừng nếu phát hiện
  chạy trên máy, build hoặc tài khoản khác.

  Lưu ý: CIS list là benchmark Windows 10 Enterprise 22H2, trong khi máy là Windows 10 Pro. Phần lớn policy vẫn áp dụng,
  nhưng một số kiểm soát Enterprise-only có thể không khả dụng. Ngoài ra, các báo cáo cùng tên sẽ bị ghi đè nếu chạy
  lại, nên lưu riêng C:\HKLab trước mỗi lượt thử nghiệm.
