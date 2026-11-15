const vscode = require('vscode');
const axios = require('axios');
const path = require('path');
const fs = require('fs');

// Bộ sưu tập thông báo lỗi (Problems panel trong VS Code)
let diagnosticCollection;

/**
 * Hàm kích hoạt Extension
 */
function activate(context) {
  diagnosticCollection = vscode.languages.createDiagnosticCollection('secshield');
  context.subscriptions.push(diagnosticCollection);

  // 1. Lệnh cấu hình API Key
  const setApiKeyCmd = vscode.commands.registerCommand('secshield.setApiKey', async () => {
    const config = vscode.workspace.getConfiguration('secshield');
    const currentKey = config.get('apiKey') || '';

    const newKey = await vscode.window.showInputBox({
      prompt: 'Nhập API Key của bạn (Lấy tại SecShield Web Portal)',
      value: currentKey,
      ignoreFocusOut: true,
      password: true
    });

    if (newKey !== undefined) {
      await config.update('apiKey', newKey.trim(), vscode.ConfigurationTarget.Global);
      vscode.window.showInformationMessage('SecShield: Đã lưu API Key thành công!');
    }
  });

  // 2. Lệnh cấu hình Server URL
  const setServerUrlCmd = vscode.commands.registerCommand('secshield.setServerUrl', async () => {
    const config = vscode.workspace.getConfiguration('secshield');
    const currentUrl = config.get('serverUrl') || 'http://localhost:5000';

    const newUrl = await vscode.window.showInputBox({
      prompt: 'Nhập địa chỉ máy chủ SecShield Scanner Backend',
      value: currentUrl,
      ignoreFocusOut: true
    });

    if (newUrl !== undefined) {
      await config.update('serverUrl', newUrl.trim(), vscode.ConfigurationTarget.Global);
      vscode.window.showInformationMessage(`SecShield: Đã cập nhật máy chủ: ${newUrl}`);
    }
  });

  // 3. Lệnh Quét Bảo Mật Dự Án
  const scanProjectCmd = vscode.commands.registerCommand('secshield.scanCurrentProject', async (uri) => {
    const config = vscode.workspace.getConfiguration('secshield');
    const serverUrl = config.get('serverUrl') || 'http://localhost:5000';
    const apiKey = config.get('apiKey') || '';

    let targetFilePath = null;
    let targetFileName = null;
    let ecosystem = null;

    // Nếu người dùng click chuột phải vào file cụ thể
    if (uri && uri.fsPath) {
      targetFilePath = uri.fsPath;
      targetFileName = path.basename(targetFilePath);
    } else {
      // Nếu không, tìm trong editor đang mở hoặc tìm trong workspace
      const activeEditor = vscode.window.activeTextEditor;
      if (activeEditor) {
        const activeName = path.basename(activeEditor.document.fileName).toLowerCase();
        if (activeName === 'package.json' || activeName.endsWith('.txt')) {
          targetFilePath = activeEditor.document.fileName;
          targetFileName = activeName;
        }
      }
    }

    // Nếu chưa xác định được file, tìm kiếm tự động trong workspace
    if (!targetFilePath) {
      const packageJsons = await vscode.workspace.findFiles('**/package.json', '**/node_modules/**', 1);
      if (packageJsons.length > 0) {
        targetFilePath = packageJsons[0].fsPath;
        targetFileName = 'package.json';
      } else {
        const reqTxts = await vscode.workspace.findFiles('**/requirements.txt', '**/venv/**', 1);
        if (reqTxts.length > 0) {
          targetFilePath = reqTxts[0].fsPath;
          targetFileName = 'requirements.txt';
        }
      }
    }

    if (!targetFilePath || !fs.existsSync(targetFilePath)) {
      vscode.window.showErrorMessage('SecShield: Không tìm thấy file package.json hoặc requirements.txt trong dự án để quét!');
      return;
    }

    // Xác định ecosystem
    if (targetFileName.toLowerCase() === 'package.json') {
      ecosystem = 'npm';
    } else {
      ecosystem = 'pypi';
    }

    const content = fs.readFileSync(targetFilePath, 'utf8');
    const projectName = vscode.workspace.name || path.basename(path.dirname(targetFilePath));

    // Thực hiện quét kèm thanh tiến trình
    await vscode.window.withProgress(
      {
        location: vscode.ProgressLocation.Notification,
        title: `SecShield: Đang phân tích ${targetFileName} qua OSV & CISA KEV...`,
        cancellable: false
      },
      async () => {
        try {
          const headers = {};
          if (apiKey) {
            headers['x-api-key'] = apiKey;
          }

          const response = await axios.post(
            `${serverUrl}/api/v1/scan/raw`,
            {
              content,
              ecosystem,
              projectName,
              filename: targetFileName
            },
            {
              headers,
              timeout: 30000
            }
          );

          const { summary, results } = response.data;

          // Cập nhật Problems Panel (Diagnostics)
          updateDiagnostics(vscode.Uri.file(targetFilePath), content, results);

          // Hiển thị thông báo kết quả
          if (summary.riskLevel === 'SAFE') {
            vscode.window.showInformationMessage(`SecShield: Dự án an toàn! Quét ${summary.totalPackages} thư viện, không phát hiện lỗ hổng.`);
          } else {
            const cisaMsg = summary.cisaKevCount > 0 ? ` [CẢNH BÁO: ${summary.cisaKevCount} LỖ HỔNG CISA KEV!]` : '';
            const msg = `SecShield [${summary.riskLevel} - Điểm: ${summary.riskScore}]: Phát hiện ${summary.vulnerablePackages}/${summary.totalPackages} thư viện có lỗ hổng CVE.${cisaMsg}`;
            
            if (summary.riskLevel === 'CRITICAL' || summary.cisaKevCount > 0) {
              vscode.window.showErrorMessage(msg, 'Xem Báo Cáo Chi Tiết').then((sel) => {
                if (sel) openReportWebview(context, response.data);
              });
            } else {
              vscode.window.showWarningMessage(msg, 'Xem Báo Cáo Chi Tiết').then((sel) => {
                if (sel) openReportWebview(context, response.data);
              });
            }
          }
        } catch (err) {
          const errMsg = err.response?.data?.error || err.message;
          vscode.window.showErrorMessage(`SecShield Quét thất bại: ${errMsg}`);
        }
      }
    );
  });

  context.subscriptions.push(setApiKeyCmd, setServerUrlCmd, scanProjectCmd);
}

/**
 * Đánh dấu vị trí dòng lỗi trực tiếp trong file mã nguồn của lập trình viên
 */
function updateDiagnostics(fileUri, fileContent, results) {
  const diagnostics = [];
  const lines = fileContent.split(/\r?\n/);

  for (const item of results) {
    if (!item.isVulnerable) continue;

    // Tìm dòng chứa package này
    for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
      const line = lines[lineIndex];
      if (line.includes(`"${item.package}"`) || line.startsWith(`${item.package}==`) || line.startsWith(`${item.package}>=`)) {
        const startPos = line.indexOf(item.package);
        const endPos = startPos + item.package.length;
        const range = new vscode.Range(lineIndex, startPos, lineIndex, endPos);

        const cveSummary = item.vulnerabilities.map((v) => v.id).slice(0, 3).join(', ');
        const fixMsg = item.fixedVersion ? `\nKhắc phục: Nâng cấp lên phiên bản >= ${item.fixedVersion}` : '';
        const cisaWarning = item.hasCisaKev ? ' [⚠️ CISA KEV - ĐANG BỊ HACKER KHAI THÁC!]' : '';

        const diagnostic = new vscode.Diagnostic(
          range,
          `[SecShield] Thư viện '${item.package}@${item.version}' dính ${item.totalVulnerabilities} lỗ hổng CVE: (${cveSummary})${cisaWarning}${fixMsg}`,
          item.hasCisaKev ? vscode.DiagnosticSeverity.Error : vscode.DiagnosticSeverity.Warning
        );

        diagnostic.source = 'SecShield SCA';
        diagnostics.push(diagnostic);
      }
    }
  }

  diagnosticCollection.set(fileUri, diagnostics);
}

/**
 * Mở Webview bảng điều khiển kết quả ngay trong VS Code
 */
function openReportWebview(context, scanData) {
  const panel = vscode.window.createWebviewPanel(
    'secshieldReport',
    `Báo Cáo SecShield: ${scanData.projectName || 'Scan'}`,
    vscode.ViewColumn.Beside,
    { enableScripts: true }
  );

  const { summary, results } = scanData;
  const riskColor = summary.riskLevel === 'CRITICAL' ? '#ef4444' : summary.riskLevel === 'HIGH' ? '#f59e0b' : summary.riskLevel === 'INCONCLUSIVE' ? '#f97316' : '#3b82f6';

  panel.webview.html = `
    <!DOCTYPE html>
    <html lang="vi">
    <head>
      <meta charset="UTF-8">
      <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #f8fafc; padding: 20px; line-height: 1.5; }
        .card { background: #1e293b; border-radius: 8px; padding: 16px; margin-bottom: 16px; border: 1px solid rgba(255,255,255,0.1); }
        .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }
        .badge-crit { background: rgba(239,68,68,0.2); color: #f87171; border: 1px solid #ef4444; }
        .badge-high { background: rgba(245,158,11,0.2); color: #fbbf24; border: 1px solid #f59e0b; }
        .badge-inconclusive { background: rgba(249,115,22,0.2); color: #fb923c; border: 1px solid #f97316; }
        .badge-safe { background: rgba(16,185,129,0.2); color: #34d399; border: 1px solid #10b981; }
        .mono { font-family: monospace; }
        h2, h3 { margin-top: 0; }
        .cisa-banner { background: linear-gradient(135deg, rgba(239,68,68,0.3), rgba(139,92,246,0.3)); border: 1px solid #ef4444; padding: 12px; border-radius: 6px; margin-bottom: 16px; }
      </style>
    </head>
    <body>
      <h2>🛡️ SecShield - Báo Cáo An Toàn Mã Nguồn</h2>
      
      <div class="card" style="border-left: 4px solid ${riskColor}">
        <div style="display: flex; justify-content: space-between; align-items: center;">
          <div>
            <h3 style="margin: 0;">${scanData.projectName || 'Dự án'}</h3>
            <div style="color: #94a3b8; font-size: 13px;">Tệp: ${scanData.fileName || 'Manifest'}</div>
          </div>
          <div style="text-align: right;">
            <span class="badge ${summary.riskLevel === 'CRITICAL' ? 'badge-crit' : summary.riskLevel === 'HIGH' ? 'badge-high' : summary.riskLevel === 'INCONCLUSIVE' ? 'badge-inconclusive' : 'badge-safe'}" style="font-size: 14px; padding: 4px 10px;">
              ${summary.riskLevel} (Điểm: ${summary.riskScore})
            </span>
          </div>
        </div>

        <div style="margin-top: 14px; display: flex; gap: 20px; font-size: 13px;">
          <div>Tổng: <strong>${summary.totalPackages}</strong></div>
          <div style="color: #f87171;">Có lỗ hổng: <strong>${summary.vulnerablePackages}</strong></div>
          <div style="color: #34d399;">An toàn: <strong>${summary.safePackages}</strong></div>
          <div style="color: #c084fc;">CISA KEV: <strong>${summary.cisaKevCount}</strong></div>
        </div>
      </div>

      ${summary.cisaKevCount > 0 ? `
        <div class="cisa-banner">
          <strong>🔥 CẢNH BÁO NGUY HIỂM:</strong> Có ${summary.cisaKevCount} lỗ hổng thuộc danh mục CISA KEV đang bị hacker khai thác thực tế trên Internet!
        </div>
      ` : ''}

      <h3>Danh Sách Thư Viện Cần Nâng Cấp:</h3>
      ${results.filter(r => r.isVulnerable).map(pkg => `
        <div class="card" style="border-left: 3px solid #ef4444;">
          <div style="display: flex; justify-content: space-between;">
            <strong class="mono" style="font-size: 15px;">${pkg.package} @ ${pkg.version}</strong>
            <span class="badge badge-crit">${pkg.totalVulnerabilities} CVEs</span>
          </div>
          ${pkg.fixedVersion ? `
            <div style="color: #38bdf8; font-size: 13px; margin-top: 6px;">
              🔧 <strong>Khắc phục:</strong> Nâng cấp lên phiên bản <code class="mono" style="background: rgba(56,189,248,0.2); padding: 2px 6px; border-radius: 4px;">>= ${pkg.fixedVersion}</code>
            </div>
          ` : ''}
          <div style="margin-top: 8px; font-size: 12px; color: #94a3b8;">
            Lỗ hổng: ${pkg.vulnerabilities.map(v => v.id).join(', ')}
          </div>
        </div>
      `).join('')}
    </body>
    </html>
  `;
}

function deactivate() {
  if (diagnosticCollection) {
    diagnosticCollection.clear();
    diagnosticCollection.dispose();
  }
}

module.exports = {
  activate,
  deactivate
};
