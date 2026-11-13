const fs = require('fs');
const AdmZip = require('adm-zip');

class ParserService {
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
      // Loại bỏ các ký tự phiên bản của npm như ^, ~, >=, <=, =, v
      const cleanVersion = versionRaw.replace(/[\^~>=<v]/g, '').trim();

      packages.push({
        name: name,
        version: cleanVersion,
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