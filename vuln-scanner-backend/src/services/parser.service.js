const fs = require('fs');
const AdmZip = require('adm-zip');

class ParserService {
  /**
   * Chuẩn hóa và trích xuất phiên bản đại diện (cận dưới) từ chuỗi khai báo npm mà vẫn giữ nguyên ngữ nghĩa khoảng phiên bản
   */
  static parseNpmVersionSpec(versionRaw) {
    const raw = versionRaw.trim();
    if (!raw) return { version: '', versionRange: raw, isVersionRange: false, isSkippable: true };

    // Các tham chiếu không phải semver registry (git, file, url, workspace, tag như latest/*)
    if (/^(git\+|https?:|file:|link:|workspace:|npm:)/i.test(raw) || /^(\*|latest|next|canary|beta|alpha)$/i.test(raw)) {
      return { version: raw, versionRange: raw, isVersionRange: true, isSkippable: true };
    }

    // Nếu có toán tử OR (||), tách nhánh đầu tiên để lấy cận dưới
    const firstBranch = raw.split('||')[0].trim();

    // Phát hiện có phải khoảng phiên bản (range) hay không
    const isRange = /[\^~><=*xX]|\s-\s|\|\|/.test(raw);

    // Xử lý khoảng gạch nối: "1.2.3 - 2.0.0" -> lấy cận dưới "1.2.3"
    let candidate = firstBranch;
    if (/\s+-\s+/.test(candidate)) {
      candidate = candidate.split(/\s+-\s+/)[0].trim();
    }

    // Xử lý chuỗi nhiều điều kiện: ">=1.2.0 <2.0.0" -> lấy token đầu tiên có số phiên bản
    const tokens = candidate.split(/\s+/).filter(Boolean);
    let selectedToken = tokens[0] || candidate;
    for (const tok of tokens) {
      if (/^[~^>=<v]*\d/.test(tok)) {
        selectedToken = tok;
        break;
      }
    }

    // Chỉ loại bỏ tiền tố toán tử (^, ~, >=, <=, >, <, =) và chữ 'v' ở ĐẦU phiên bản (không xóa 'v' trong -dev)
    let clean = selectedToken
      .replace(/^(>=|<=|>|<|=|\^|~)+/, '')
      .replace(/^v(?=\d)/i, '')
      .trim();

    // Chuẩn hóa x-range như "1.2.x" -> "1.2.0", "1.x" -> "1.0.0"
    if (/^\d+(\.(\d+|x|X|\*)){0,2}$/.test(clean)) {
      const parts = clean.split('.');
      while (parts.length < 3) parts.push('0');
      clean = parts.map((p) => (/^[xX*]$/.test(p) ? '0' : p)).join('.');
    }

    return {
      version: clean || raw,
      versionRange: raw,
      isVersionRange: isRange,
      isSkippable: false
    };
  }

  /**
   * Bóc tách chuỗi JSON của package.json
   */
  static parsePackageJsonContent(rawContent) {
    const parsedJson = JSON.parse(rawContent);
    const packages = [];

    // Gộp cả dependencies và devDependencies
    const allDependencies = {
      ...(parsedJson.dependencies || {}),
      ...(parsedJson.devDependencies || {})
    };

    for (const [name, versionRaw] of Object.entries(allDependencies)) {
      if (typeof versionRaw !== 'string') continue;
      const parsed = this.parseNpmVersionSpec(versionRaw);
      if (parsed.isSkippable || !parsed.version) continue;

      packages.push({
        name: name,
        version: parsed.version,
        versionRange: parsed.versionRange,
        isVersionRange: parsed.isVersionRange,
        ecosystem: 'npm'
      });
    }

    return packages;
  }

  /**
   * Bóc tách file package.json (Hệ sinh thái npm của Node.js)
   */
  static parsePackageJson(filePath) {
    const rawContent = fs.readFileSync(filePath, 'utf-8');
    return this.parsePackageJsonContent(rawContent);
  }

  /**
   * Bóc tách chuỗi text của requirements.txt
   */
  static parseRequirementsTxtContent(rawContent) {
    const lines = rawContent.split(/\r?\n/);
    const packages = [];

    for (const line of lines) {
      const trimmedLine = line.trim();
      // Bỏ qua dòng trống hoặc dòng comment
      if (!trimmedLine || trimmedLine.startsWith('#')) continue;

      // Match định dạng: package==1.0.0 hoặc package>=1.0.0, v.v.
      const match = trimmedLine.match(/^([a-zA-Z0-9_\-\.]+)(?:==|>=|<=|~=)(.+)$/);
      if (match) {
        packages.push({
          name: match[1].trim(),
          version: match[2].trim(),
          ecosystem: 'PyPI'
        });
      }
    }

    return packages;
  }

  /**
   * Bóc tách file requirements.txt (Hệ sinh thái PyPI của Python)
   */
  static parseRequirementsTxt(filePath) {
    const rawContent = fs.readFileSync(filePath, 'utf-8');
    return this.parseRequirementsTxtContent(rawContent);
  }

  /**
   * Bóc tách file nén .zip, tìm kiếm package.json hoặc requirements.txt bên trong
   */
  static parseZipFile(zipFilePath) {
    const zip = new AdmZip(zipFilePath);
    const zipEntries = zip.getEntries();

    let foundPackageJson = null;
    let foundRequirementsTxt = null;

    for (const entry of zipEntries) {
      if (entry.isDirectory) continue;
      const entryName = entry.entryName.toLowerCase();

      // Ưu tiên file ở root directory hoặc gần root nhất
      if (entryName.endsWith('package.json') && !entryName.includes('node_modules')) {
        foundPackageJson = entry;
      } else if (entryName.endsWith('requirements.txt') && !entryName.includes('venv') && !entryName.includes('.env')) {
        foundRequirementsTxt = entry;
      }
    }

    if (foundPackageJson) {
      const content = foundPackageJson.getData().toString('utf8');
      return {
        fileType: 'npm',
        manifestFile: foundPackageJson.name,
        packages: this.parsePackageJsonContent(content)
      };
    }

    if (foundRequirementsTxt) {
      const content = foundRequirementsTxt.getData().toString('utf8');
      return {
        fileType: 'pypi',
        manifestFile: foundRequirementsTxt.name,
        packages: this.parseRequirementsTxtContent(content)
      };
    }

    throw new Error('Không tìm thấy file package.json hoặc requirements.txt trong file nén .zip');
  }
}

module.exports = ParserService;