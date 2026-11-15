import {
  Document,
  Packer,
  Paragraph,
  TextRun,
  Table,
  TableRow,
  TableCell,
  WidthType,
  AlignmentType,
  HeadingLevel,
  BorderStyle,
  convertInchesToTwip
} from 'docx';

function decodeUtf8Safe(str) {
  if (!str) return '';
  try {
    if (/[ÄÅá»º·]/.test(str)) {
      return decodeURIComponent(escape(str));
    }
  } catch (e) {}
  return str;
}

const tableBorderLight = {
  top: { style: BorderStyle.SINGLE, size: 1, color: 'CBD5E1' },
  bottom: { style: BorderStyle.SINGLE, size: 1, color: 'CBD5E1' },
  left: { style: BorderStyle.SINGLE, size: 1, color: 'CBD5E1' },
  right: { style: BorderStyle.SINGLE, size: 1, color: 'CBD5E1' },
  insideHorizontal: { style: BorderStyle.SINGLE, size: 1, color: 'E2E8F0' },
  insideVertical: { style: BorderStyle.SINGLE, size: 1, color: 'E2E8F0' }
};

const cellPaddingStandard = {
  top: 120,
  bottom: 120,
  left: 150,
  right: 150
};

const FONT_NAME = 'Times New Roman';

export async function generateWordReport(scanData) {
  if (!scanData) throw new Error('Không có dữ liệu báo cáo');

  const {
    summary = {},
    results = [],
    projectName,
    fileName,
    fileType,
    scannedAt
  } = scanData;

  const displayProject = decodeUtf8Safe(projectName) || 'Dự án phần mềm';
  const displayFile = decodeUtf8Safe(fileName) || 'manifest.json';
  const displayEco = (fileType || 'npm').toUpperCase();
  const scanDate = scannedAt ? new Date(scannedAt).toLocaleString('vi-VN') : new Date().toLocaleString('vi-VN');

  const vulnerablePackages = results.filter((p) => p.isVulnerable);
  const totalVulnsCount = vulnerablePackages.reduce((acc, p) => acc + (p.vulnerabilities?.length || 0), 0);

  const docChildren = [];

  // ==================== 1. TIÊU ĐỀ BÁO CÁO ====================
  docChildren.push(
    new Paragraph({
      alignment: AlignmentType.CENTER,
      spacing: { before: 200, after: 80 },
      children: [
        new TextRun({
          text: 'BÁO CÁO DANH SÁCH LỖ HỔNG BẢO MẬT',
          bold: true,
          size: 34, // 17pt
          color: '0F172A',
          font: FONT_NAME
        })
      ]
    }),
    new Paragraph({
      alignment: AlignmentType.CENTER,
      spacing: { after: 260 },
      children: [
        new TextRun({
          text: 'Danh sách chi tiết các lỗ hổng mã nguồn mở và hướng dẫn khắc phục',
          italics: true,
          size: 24, // 12pt
          color: '475569',
          font: FONT_NAME
        })
      ]
    })
  );

  // ==================== 2. BẢNG THÔNG TIN TỔNG QUAN ====================
  docChildren.push(
    new Paragraph({
      heading: HeadingLevel.HEADING_2,
      spacing: { before: 180, after: 120 },
      children: [
        new TextRun({
          text: 'I. THÔNG TIN CHUNG VÀ TỔNG QUAN KẾT QUẢ',
          bold: true,
          size: 26,
          color: '0F172A',
          font: FONT_NAME
        })
      ]
    })
  );

  const metaTable = new Table({
    width: { size: 100, type: WidthType.PERCENTAGE },
    borders: tableBorderLight,
    rows: [
      new TableRow({
        children: [
          new TableCell({
            width: { size: 25, type: WidthType.PERCENTAGE },
            margins: cellPaddingStandard,
            shading: { fill: 'F8FAFC' },
            children: [new Paragraph({ children: [new TextRun({ text: 'Tên dự án:', bold: true, font: FONT_NAME })] })]
          }),
          new TableCell({
            width: { size: 25, type: WidthType.PERCENTAGE },
            margins: cellPaddingStandard,
            children: [new Paragraph({ children: [new TextRun({ text: displayProject, font: FONT_NAME })] })]
          }),
          new TableCell({
            width: { size: 25, type: WidthType.PERCENTAGE },
            margins: cellPaddingStandard,
            shading: { fill: 'F8FAFC' },
            children: [new Paragraph({ children: [new TextRun({ text: 'Thời gian quét:', bold: true, font: FONT_NAME })] })]
          }),
          new TableCell({
            width: { size: 25, type: WidthType.PERCENTAGE },
            margins: cellPaddingStandard,
            children: [new Paragraph({ children: [new TextRun({ text: scanDate, font: FONT_NAME })] })]
          })
        ]
      }),
      new TableRow({
        children: [
          new TableCell({
            width: { size: 25, type: WidthType.PERCENTAGE },
            margins: cellPaddingStandard,
            shading: { fill: 'F8FAFC' },
            children: [new Paragraph({ children: [new TextRun({ text: 'Tệp phân tích:', bold: true, font: FONT_NAME })] })]
          }),
          new TableCell({
            width: { size: 25, type: WidthType.PERCENTAGE },
            margins: cellPaddingStandard,
            children: [new Paragraph({ children: [new TextRun({ text: `${displayFile} (${displayEco})`, font: FONT_NAME })] })]
          }),
          new TableCell({
            width: { size: 25, type: WidthType.PERCENTAGE },
            margins: cellPaddingStandard,
            shading: { fill: 'F8FAFC' },
            children: [new Paragraph({ children: [new TextRun({ text: 'Cấp độ rủi ro:', bold: true, font: FONT_NAME })] })]
          }),
          new TableCell({
            width: { size: 25, type: WidthType.PERCENTAGE },
            margins: cellPaddingStandard,
            children: [
              new Paragraph({
                children: [
                  new TextRun({
                    text: `${summary.riskLevel || 'N/A'} (Điểm: ${summary.riskScore ?? 0}/100)`,
                    bold: true,
                    color: summary.riskLevel === 'CRITICAL' ? 'DC2626' : summary.riskLevel === 'HIGH' ? 'EA580C' : '2563EB',
                    font: FONT_NAME
                  })
                ]
              })
            ]
          })
        ]
      }),
      new TableRow({
        children: [
          new TableCell({
            width: { size: 25, type: WidthType.PERCENTAGE },
            margins: cellPaddingStandard,
            shading: { fill: 'F8FAFC' },
            children: [new Paragraph({ children: [new TextRun({ text: 'Tổng số thư viện:', bold: true, font: FONT_NAME })] })]
          }),
          new TableCell({
            width: { size: 25, type: WidthType.PERCENTAGE },
            margins: cellPaddingStandard,
            children: [new Paragraph({ children: [new TextRun({ text: `${summary.totalPackages ?? results.length}`, font: FONT_NAME })] })]
          }),
          new TableCell({
            width: { size: 25, type: WidthType.PERCENTAGE },
            margins: cellPaddingStandard,
            shading: { fill: 'F8FAFC' },
            children: [new Paragraph({ children: [new TextRun({ text: 'Thư viện dính lỗi:', bold: true, font: FONT_NAME })] })]
          }),
          new TableCell({
            width: { size: 25, type: WidthType.PERCENTAGE },
            margins: cellPaddingStandard,
            children: [
              new Paragraph({
                children: [
                  new TextRun({
                    text: `${vulnerablePackages.length} thư viện (Tổng ${totalVulnsCount} CVEs)`,
                    bold: vulnerablePackages.length > 0,
                    color: vulnerablePackages.length > 0 ? 'DC2626' : '16A34A',
                    font: FONT_NAME
                  })
                ]
              })
            ]
          })
        ]
      })
    ]
  });

  docChildren.push(metaTable);
  docChildren.push(new Paragraph({ spacing: { after: 200 } }));

  // ==================== 3. BẢNG TỔNG HỢP CÁC GÓI CÓ LỖ HỔNG ====================
  docChildren.push(
    new Paragraph({
      heading: HeadingLevel.HEADING_2,
      spacing: { before: 200, after: 120 },
      children: [
        new TextRun({
          text: `II. BẢNG TỔNG HỢP CÁC GÓI THƯ VIỆN PHÁT HIỆN LỖ HỔNG (${vulnerablePackages.length} GÓI)`,
          bold: true,
          size: 26,
          color: '0F172A',
          font: FONT_NAME
        })
      ]
    })
  );

  if (vulnerablePackages.length === 0) {
    const errorCount = summary.errorPackages || results.filter((p) => p.hasScanError).length;
    if (errorCount > 0) {
      docChildren.push(
        new Paragraph({
          spacing: { after: 200 },
          children: [
            new TextRun({
              text: `⚠️ Cảnh báo phạm vi dữ liệu (AUD-01): Có ${errorCount} gói thư viện gặp sự cố kết nối tới nguồn Google OSV. Trong phạm vi các gói đã xác minh thành công (${summary.safePackages ?? (results.length - errorCount)} gói), không phát hiện lỗ hổng. Chưa thể kết luận an toàn tuyệt đối cho toàn bộ dự án.`,
              bold: true,
              color: 'B45309',
              font: FONT_NAME
            })
          ]
        })
      );
    } else {
      docChildren.push(
        new Paragraph({
          spacing: { after: 200 },
          children: [
            new TextRun({
              text: '✓ Không phát hiện bất kỳ lỗ hổng bảo mật nào trong các thư viện phụ thuộc của dự án này.',
              bold: true,
              color: '16A34A',
              font: FONT_NAME
            })
          ]
        })
      );
    }
  } else {
    const summaryTableRows = [
      new TableRow({
        children: [
          new TableCell({
            width: { size: 8, type: WidthType.PERCENTAGE },
            margins: cellPaddingStandard,
            shading: { fill: 'E2E8F0' },
            children: [new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: 'STT', bold: true, font: FONT_NAME })] })]
          }),
          new TableCell({
            width: { size: 24, type: WidthType.PERCENTAGE },
            margins: cellPaddingStandard,
            shading: { fill: 'E2E8F0' },
            children: [new Paragraph({ children: [new TextRun({ text: 'Tên thư viện', bold: true, font: FONT_NAME })] })]
          }),
          new TableCell({
            width: { size: 15, type: WidthType.PERCENTAGE },
            margins: cellPaddingStandard,
            shading: { fill: 'E2E8F0' },
            children: [new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: 'Phiên bản', bold: true, font: FONT_NAME })] })]
          }),
          new TableCell({
            width: { size: 15, type: WidthType.PERCENTAGE },
            margins: cellPaddingStandard,
            shading: { fill: 'E2E8F0' },
            children: [new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: 'Số lỗi CVE', bold: true, font: FONT_NAME })] })]
          }),
          new TableCell({
            width: { size: 18, type: WidthType.PERCENTAGE },
            margins: cellPaddingStandard,
            shading: { fill: 'E2E8F0' },
            children: [new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: 'CISA KEV / PoC', bold: true, font: FONT_NAME })] })]
          }),
          new TableCell({
            width: { size: 20, type: WidthType.PERCENTAGE },
            margins: cellPaddingStandard,
            shading: { fill: 'E2E8F0' },
            children: [new Paragraph({ children: [new TextRun({ text: 'Bản vá khuyến nghị', bold: true, font: FONT_NAME })] })]
          })
        ]
      })
    ];

    vulnerablePackages.forEach((pkg, index) => {
      summaryTableRows.push(
        new TableRow({
          children: [
            new TableCell({
              width: { size: 8, type: WidthType.PERCENTAGE },
              margins: cellPaddingStandard,
              children: [new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: `${index + 1}`, font: FONT_NAME })] })]
            }),
            new TableCell({
              width: { size: 24, type: WidthType.PERCENTAGE },
              margins: cellPaddingStandard,
              children: [new Paragraph({ children: [new TextRun({ text: pkg.package, bold: true, font: FONT_NAME })] })]
            }),
            new TableCell({
              width: { size: 15, type: WidthType.PERCENTAGE },
              margins: cellPaddingStandard,
              children: [new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: `v${pkg.version}`, font: FONT_NAME })] })]
            }),
            new TableCell({
              width: { size: 15, type: WidthType.PERCENTAGE },
              margins: cellPaddingStandard,
              children: [
                new Paragraph({
                  alignment: AlignmentType.CENTER,
                  children: [
                    new TextRun({
                      text: `${pkg.totalVulnerabilities || pkg.vulnerabilities?.length || 0} CVEs`,
                      bold: true,
                      color: 'DC2626',
                      font: FONT_NAME
                    })
                  ]
                })
              ]
            }),
            new TableCell({
              width: { size: 18, type: WidthType.PERCENTAGE },
              margins: cellPaddingStandard,
              children: [
                new Paragraph({
                  alignment: AlignmentType.CENTER,
                  children: [
                    new TextRun({
                      text: pkg.hasCisaKev ? '⚠️ CISA KEV' : pkg.vulnerabilities?.some((v) => v.hasExploitDb) ? 'Có Exploit PoC' : 'Không',
                      bold: pkg.hasCisaKev,
                      color: pkg.hasCisaKev ? 'DC2626' : '475569',
                      font: FONT_NAME
                    })
                  ]
                })
              ]
            }),
            new TableCell({
              width: { size: 20, type: WidthType.PERCENTAGE },
              margins: cellPaddingStandard,
              children: [
                new Paragraph({
                  children: [
                    new TextRun({
                      text: pkg.fixedVersion ? `>= ${pkg.fixedVersion}` : 'Chưa có bản vá',
                      bold: !!pkg.fixedVersion,
                      color: pkg.fixedVersion ? '0284C7' : 'EA580C',
                      font: FONT_NAME
                    })
                  ]
                })
              ]
            })
          ]
        })
      );
    });

    docChildren.push(
      new Table({
        width: { size: 100, type: WidthType.PERCENTAGE },
        borders: tableBorderLight,
        rows: summaryTableRows
      })
    );
    docChildren.push(new Paragraph({ spacing: { after: 250 } }));
  }

  // ==================== 4. CHI TIẾT TẤT CẢ CÁC LỖ HỔNG ====================
  docChildren.push(
    new Paragraph({
      heading: HeadingLevel.HEADING_2,
      spacing: { before: 200, after: 120 },
      children: [
        new TextRun({
          text: 'III. CHI TIẾT TẤT CẢ CÁC LỖ HỔNG BẢO MẬT PHÁT HIỆN ĐƯỢC',
          bold: true,
          size: 26,
          color: '0F172A',
          font: FONT_NAME
        })
      ]
    }),
    new Paragraph({
      spacing: { after: 200 },
      children: [
        new TextRun({
          text: 'Dưới đây là danh sách phân tích chi tiết từng lỗ hổng bảo mật, mức độ nguy hiểm, mã tham chiếu CVE và hướng dẫn khắc phục cụ thể cho từng thành phần.',
          italics: true,
          size: 24,
          color: '475569',
          font: FONT_NAME
        })
      ]
    })
  );

  if (vulnerablePackages.length === 0) {
    docChildren.push(
      new Paragraph({
        children: [
          new TextRun({
            text: 'Không có lỗi bảo mật nào để hiển thị.',
            font: FONT_NAME
          })
        ]
      })
    );
  } else {
    vulnerablePackages.forEach((pkg, pIdx) => {
      // Tiêu đề cho từng package
      docChildren.push(
        new Paragraph({
          heading: HeadingLevel.HEADING_3,
          spacing: { before: 240, after: 80 },
          children: [
            new TextRun({
              text: `${pIdx + 1}. Thư viện: ${pkg.package} (Phiên bản đang dùng: v${pkg.version})`,
              bold: true,
              size: 24,
              color: '1E3A8A',
              font: FONT_NAME
            })
          ]
        }),
        new Paragraph({
          spacing: { after: 120 },
          children: [
            new TextRun({ text: '• Bản vá an toàn khuyến nghị: ', bold: true, font: FONT_NAME }),
            new TextRun({
              text: pkg.fixedVersion ? `Nâng cấp lên phiên bản >= ${pkg.fixedVersion}` : 'Chưa có bản vá chính thức, khuyến nghị theo dõi mã nguồn',
              bold: true,
              color: pkg.fixedVersion ? '0284C7' : 'EA580C',
              font: FONT_NAME
            }),
            new TextRun({ text: ` | Tổng số lỗi: ${pkg.vulnerabilities?.length || 0} CVEs`, font: FONT_NAME })
          ]
        })
      );

      // Chi tiết từng lỗi CVE của package đó
      (pkg.vulnerabilities || []).forEach((vuln, vIdx) => {
        const severityColor =
          vuln.severity === 'CRITICAL' ? 'DC2626' :
          vuln.severity === 'HIGH' ? 'EA580C' :
          vuln.severity === 'MEDIUM' ? '2563EB' : '6B7280';

        const vulnDetailRows = [
          new TableRow({
            children: [
              new TableCell({
                width: { size: 25, type: WidthType.PERCENTAGE },
                margins: cellPaddingStandard,
                shading: { fill: 'F1F5F9' },
                children: [new Paragraph({ children: [new TextRun({ text: 'Mã Lỗ Hổng (ID):', bold: true, font: FONT_NAME })] })]
              }),
              new TableCell({
                width: { size: 75, type: WidthType.PERCENTAGE },
                margins: cellPaddingStandard,
                children: [
                  new Paragraph({
                    children: [
                      new TextRun({ text: vuln.id, bold: true, font: FONT_NAME, color: '1E3A8A' }),
                      vuln.aliases && vuln.aliases.length > 0
                        ? new TextRun({ text: ` (Bí danh: ${vuln.aliases.join(', ')})`, font: FONT_NAME, color: '475569' })
                        : new TextRun('')
                    ]
                  })
                ]
              })
            ]
          }),
          new TableRow({
            children: [
              new TableCell({
                width: { size: 25, type: WidthType.PERCENTAGE },
                margins: cellPaddingStandard,
                shading: { fill: 'F1F5F9' },
                children: [new Paragraph({ children: [new TextRun({ text: 'Mức độ nghiêm trọng:', bold: true, font: FONT_NAME })] })]
              }),
              new TableCell({
                width: { size: 75, type: WidthType.PERCENTAGE },
                margins: cellPaddingStandard,
                children: [
                  new Paragraph({
                    children: [
                      new TextRun({
                        text: vuln.severity || 'UNKNOWN',
                        bold: true,
                        color: severityColor,
                        font: FONT_NAME
                      }),
                      vuln.isCisaKev
                        ? new TextRun({ text: '  [CẢNH BÁO: CISA KEV - ĐANG BỊ TIN TẶC TẤN CÔNG THỰC TẾ]', bold: true, color: 'DC2626', font: FONT_NAME })
                        : new TextRun('')
                    ]
                  })
                ]
              })
            ]
          }),
          new TableRow({
            children: [
              new TableCell({
                width: { size: 25, type: WidthType.PERCENTAGE },
                margins: cellPaddingStandard,
                shading: { fill: 'F1F5F9' },
                children: [new Paragraph({ children: [new TextRun({ text: 'Tóm tắt lỗi:', bold: true, font: FONT_NAME })] })]
              }),
              new TableCell({
                width: { size: 75, type: WidthType.PERCENTAGE },
                margins: cellPaddingStandard,
                children: [
                  new Paragraph({
                    children: [new TextRun({ text: vuln.summary || 'Không có mô tả ngắn', font: FONT_NAME })]
                  })
                ]
              })
            ]
          })
        ];

        if (vuln.details && vuln.details.trim() && vuln.details !== vuln.summary) {
          const cleanDetails = vuln.details.length > 600 ? vuln.details.substring(0, 600) + '...' : vuln.details;
          vulnDetailRows.push(
            new TableRow({
              children: [
                new TableCell({
                  width: { size: 25, type: WidthType.PERCENTAGE },
                  margins: cellPaddingStandard,
                  shading: { fill: 'F1F5F9' },
                  children: [new Paragraph({ children: [new TextRun({ text: 'Chi tiết kỹ thuật:', bold: true, font: FONT_NAME })] })]
                }),
                new TableCell({
                  width: { size: 75, type: WidthType.PERCENTAGE },
                  margins: cellPaddingStandard,
                  children: [
                    new Paragraph({
                      children: [new TextRun({ text: cleanDetails, font: FONT_NAME, size: 22 })]
                    })
                  ]
                })
              ]
            })
          );
        }

        if (vuln.isCisaKev && vuln.cisaKevDetails) {
          vulnDetailRows.push(
            new TableRow({
              children: [
                new TableCell({
                  width: { size: 25, type: WidthType.PERCENTAGE },
                  margins: cellPaddingStandard,
                  shading: { fill: 'FEF2F2' },
                  children: [new Paragraph({ children: [new TextRun({ text: 'Chỉ thị CISA KEV:', bold: true, color: 'DC2626', font: FONT_NAME })] })]
                }),
                new TableCell({
                  width: { size: 75, type: WidthType.PERCENTAGE },
                  margins: cellPaddingStandard,
                  shading: { fill: 'FEF2F2' },
                  children: [
                    new Paragraph({
                      children: [
                        new TextRun({ text: `Tên chiến dịch: ${vuln.cisaKevDetails.vulnerabilityName || ''}\n`, bold: true, font: FONT_NAME, size: 22 }),
                        new TextRun({ text: `Hành động bắt buộc: ${vuln.cisaKevDetails.requiredAction || ''}`, font: FONT_NAME, size: 22 })
                      ]
                    })
                  ]
                })
              ]
            })
          );
        }

        if (vuln.hasExploitDb && vuln.exploitDbList?.length > 0) {
          const edbTitles = vuln.exploitDbList.map((e) => `[EDB-${e.id}] ${e.description}`).slice(0, 3).join('; ');
          vulnDetailRows.push(
            new TableRow({
              children: [
                new TableCell({
                  width: { size: 25, type: WidthType.PERCENTAGE },
                  margins: cellPaddingStandard,
                  shading: { fill: 'FFFBEB' },
                  children: [new Paragraph({ children: [new TextRun({ text: 'Mã khai thác Exploit-DB:', bold: true, color: 'D97706', font: FONT_NAME })] })]
                }),
                new TableCell({
                  width: { size: 75, type: WidthType.PERCENTAGE },
                  margins: cellPaddingStandard,
                  shading: { fill: 'FFFBEB' },
                  children: [
                    new Paragraph({
                      children: [new TextRun({ text: `Đã có mã PoC công khai: ${edbTitles}`, font: FONT_NAME, size: 22 })]
                    })
                  ]
                })
              ]
            })
          );
        }

        if (vuln.references && vuln.references.length > 0) {
          vulnDetailRows.push(
            new TableRow({
              children: [
                new TableCell({
                  width: { size: 25, type: WidthType.PERCENTAGE },
                  margins: cellPaddingStandard,
                  shading: { fill: 'F1F5F9' },
                  children: [new Paragraph({ children: [new TextRun({ text: 'Liên kết tham chiếu:', bold: true, font: FONT_NAME })] })]
                }),
                new TableCell({
                  width: { size: 75, type: WidthType.PERCENTAGE },
                  margins: cellPaddingStandard,
                  children: [
                    new Paragraph({
                      children: [
                        new TextRun({
                          text: vuln.references.slice(0, 3).join('\n'),
                          font: FONT_NAME,
                          size: 20,
                          color: '2563EB'
                        })
                      ]
                    })
                  ]
                })
              ]
            })
          );
        }

        docChildren.push(
          new Paragraph({
            spacing: { before: 100, after: 40 },
            children: [
              new TextRun({
                text: `${pIdx + 1}.${vIdx + 1}. Lỗ hổng ${vuln.id}`,
                bold: true,
                size: 22,
                color: '0F172A',
                font: FONT_NAME
              })
            ]
          }),
          new Table({
            width: { size: 100, type: WidthType.PERCENTAGE },
            borders: tableBorderLight,
            rows: vulnDetailRows
          }),
          new Paragraph({ spacing: { after: 120 } })
        );
      });
    });
  }

  // Khởi tạo Document của docx với font mặc định Times New Roman
  const doc = new Document({
    styles: {
      default: {
        document: {
          run: {
            font: FONT_NAME,
            size: 24 // 12pt standard Times New Roman
          }
        }
      }
    },
    sections: [
      {
        properties: {
          page: {
            margin: {
              top: convertInchesToTwip(1),
              bottom: convertInchesToTwip(1),
              left: convertInchesToTwip(1),
              right: convertInchesToTwip(1)
            }
          }
        },
        children: docChildren
      }
    ]
  });

  return doc;
}

export async function exportWordReport(scanData) {
  try {
    const doc = await generateWordReport(scanData);
    const blob = await Packer.toBlob(doc);
    const projectName = scanData.projectName || 'scan';
    const cleanFileName = `Bao_Cao_Lo_Hong_${projectName.replace(/[^a-zA-Z0-9_-]/g, '_')}_${Date.now()}.docx`;

    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = cleanFileName;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    return true;
  } catch (error) {
    console.error('Lỗi khi xuất file Word:', error);
    alert('Không thể tạo file Word: ' + error.message);
    return false;
  }
}
