// generate_allocationinfo.js
const fs = require('fs');
const path = require('path');

// 1. 读取 yaml 提取原始三级简码 (tripleExist)
const yamlPath = path.join(__dirname, 'wubi98_base.dict.yaml');
const yamlContent = fs.readFileSync(yamlPath, 'utf-8');
const yamlLines = yamlContent.split(/\r?\n/);

const tripleExist = new Map();
let inData = false;
for (const line of yamlLines) {
  const trimmed = line.trim();
  if (trimmed === '' || trimmed.startsWith('#')) continue;
  if (!inData) {
    if (line.includes('\t')) inData = true;
    else continue;
  }
  const parts = line.split('\t');
  if (parts.length < 2) continue;
  const text = parts[0].trim();
  if ([...text].length !== 1) continue;
  const code = parts[1].trim().toLowerCase();
  if (code.length === 3 && /^[a-y]{3}$/.test(code)) {
    if (!tripleExist.has(code)) tripleExist.set(code, text);
  }
}

// 2. 读取 triplecode.js
const triplePath = path.join(__dirname, 'triplecode.js');
const tripleContent = fs.readFileSync(triplePath, 'utf-8');
const match = tripleContent.match(/var\s+TRIPLE_CODES\s*=\s*({[\s\S]*});/);
if (!match) { console.error('无法解析 triplecode.js'); process.exit(1); }
const TRIPLE_CODES = JSON.parse(match[1]);

// 3. 固定替换的11个三码
const fixedReplace = {
  aaa: '蘽',
  dhf: '猋',
  fbn: '壵',
  mgk: '赑',
  nav: '焱',
  yey: '譶',
  ypi: '矗',
  rqy: '毳',
  svf: '喿',
  ntc: '惢',
  ygd: '劦'
};

const FIXED_TRIPLE_CODE = { ...fixedReplace };

// 4. 收集特别分配：原始三级简码存在，且与最终值不同，且不是固定替换
const SPECIAL_ALLOCATION = {};
for (const [code, original] of tripleExist) {
  if (!(code in TRIPLE_CODES)) continue; // 理论不应发生
  const finalVal = TRIPLE_CODES[code];
  if (finalVal !== original && !(code in fixedReplace)) {
    SPECIAL_ALLOCATION[code] = finalVal;
  }
}

// 5. 输出 allocationinfo.js (压缩)
const output = 'var FIXED_TRIPLE_CODE=' + JSON.stringify(FIXED_TRIPLE_CODE) +
  ';var SPECIAL_ALLOCATION=' + JSON.stringify(SPECIAL_ALLOCATION) + ';';
fs.writeFileSync(path.join(__dirname, 'allocationinfo.js'), output, 'utf-8');
console.log('allocationinfo.js 生成成功。');
console.log(`FIXED_TRIPLE_CODE 条目: ${Object.keys(FIXED_TRIPLE_CODE).length}`);
console.log(`SPECIAL_ALLOCATION 条目: ${Object.keys(SPECIAL_ALLOCATION).length}`);