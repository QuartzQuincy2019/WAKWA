// encryptE.js (E 加密器 v6 — 固定6位编码，1000个6字母KGM，无填充)
(function () {
  if (typeof DOUBLE_CODES === 'undefined') throw new Error('请先加载 doublecode.js');
  if (typeof TRIPLE_CODES === 'undefined') throw new Error('请先加载 triplecode.js');

  // ========== 基础工具 ==========
  const bytesToHex = bytes => Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  const hexToBytes = hex => {
    if (hex.length % 2) throw new Error('无效十六进制');
    return new Uint8Array(hex.length / 2).map((_, i) => parseInt(hex.substr(i * 2, 2), 16));
  };

  function mulberry32(seed) {
    return () => {
      seed |= 0; seed = (seed + 0x6d2b79f5) | 0;
      let t = Math.imul(seed ^ seed >>> 15, 1 | seed);
      t = (t + Math.imul(t ^ t >>> 7, 61 | t)) ^ t;
      return ((t ^ t >>> 14) >>> 0) / 4294967296;
    };
  }
  const uint32FromBytes = bytes => new DataView(bytes.buffer, bytes.byteOffset, 4).getUint32(0, true);
  const shuffleArray = (arr, rand) => {
    for (let i = arr.length - 1; i > 0; i--) {
      const j = Math.floor(rand() * (i + 1));
      [arr[i], arr[j]] = [arr[j], arr[i]];
    }
    return arr;
  };

  // 生成范围内的质数数组
  function primesInRange(min, max) {
    const sieve = new Uint8Array(max + 1).fill(1);
    sieve[0] = sieve[1] = 0;
    for (let i = 2; i * i <= max; i++) {
      if (sieve[i]) {
        for (let j = i * i; j <= max; j += i) sieve[j] = 0;
      }
    }
    const result = [];
    for (let i = min; i <= max; i++) if (sieve[i]) result.push(i);
    return result;
  }

  // 预生成所需质数表
  const P_1000_9999 = primesInRange(1000, 9999);
  const P_100000_999999 = primesInRange(100000, 999999);
  const P_50_600 = primesInRange(50, 600);

  const MOD = 2n ** 27n;                // 134217728n
  const LETTERS_ALL = 'abcdefghijklmnopqrstuvwxy';

  // ========== 固定6位24进制编码 (BigInt) ==========
  function toBase24Fixed6(value, letters) {
    const ZERO = letters[0];
    let digits = '';
    let v = value;
    for (let i = 0; i < 6; i++) {
      const rem = Number(v % 24n);
      digits = letters[rem] + digits;
      v = v / 24n;
    }
    return digits;
  }

  function fromBase24Fixed6(str, letters) {
    let val = 0n;
    for (const ch of str) {
      const idx = letters.indexOf(ch);
      if (idx === -1) throw new Error(`非法字母 '${ch}'`);
      val = val * 24n + BigInt(idx);
    }
    return val;
  }

  // ========== 映射表操作 ==========
  function shuffleMap(originalMap, seedBytes) {
    const keys = Object.keys(originalMap);
    const values = keys.map(k => originalMap[k]);
    const rand = mulberry32(uint32FromBytes(seedBytes));
    const shuffledValues = shuffleArray([...values], rand);
    const newMap = {};
    keys.forEach((k, idx) => { newMap[k] = shuffledValues[idx]; });
    return newMap;
  }

  // 生成1000个不重复的6字母KGM（使用完整a-y字母表）
  function generateKGM(seedBytes) {
    const rand = mulberry32(uint32FromBytes(seedBytes));
    const kgm = new Set();
    while (kgm.size < 1000) {
      let str = '';
      for (let i = 0; i < 6; i++) {
        str += LETTERS_ALL[Math.floor(rand() * 25)];
      }
      kgm.add(str);
    }
    return Array.from(kgm);
  }

  // ========== 密钥派生 ==========
  async function deriveMasterKeyFromPassword(password, salt) {
    const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits(
      { name: 'PBKDF2', salt, iterations: 600000, hash: 'SHA-256' }, key, 256
    );
    return bytesToHex(new Uint8Array(bits));
  }

  async function deriveAllParams(masterKeyBytes, salt, mode, compact) {
    const masterKey = await crypto.subtle.importKey('raw', masterKeyBytes, 'HKDF', false, ['deriveBits']);
    const enc = new TextEncoder();
    const derive = async (info) => {
      const bits = await crypto.subtle.deriveBits(
        { name: 'HKDF', hash: 'SHA-256', salt, info: enc.encode(info) }, masterKey, 256
      );
      return new Uint8Array(bits);
    };

    const [elimS, ascS, weaveS, stepS, kgmS, mapS] = await Promise.all([
      derive('eliminated'), derive('ascending'), derive('weaving'),
      derive('step'), derive('kgm'), derive('map')
    ]);

    // eliminated 字母 (影响编码字母表)
    const eliminated = LETTERS_ALL[elimS[0] % 25];
    const letters = LETTERS_ALL.replace(eliminated, '');   // 24个字母

    // ascending 参数 (BigInt)
    const ascView = new DataView(ascS.buffer);
    const idxAdd = ascView.getUint16(0, true) % P_1000_9999.length;
    const addition = BigInt(P_1000_9999[idxAdd]);
    const idxPtr = ascView.getUint16(2, true) % P_1000_9999.length;
    let pointer = BigInt(P_1000_9999[idxPtr]);
    while (pointer === addition) {
      pointer = BigInt(P_1000_9999[(idxPtr + 1) % P_1000_9999.length]);
    }
    const idxProd = ascView.getUint16(4, true) % P_100000_999999.length;
    let producer = BigInt(P_100000_999999[idxProd]);
    while (producer === addition || producer === pointer) {
      producer = BigInt(P_100000_999999[(idxProd + 1) % P_100000_999999.length]);
    }

    // weaving 参数 (BigInt, 范围 1 ~ 2^23-1)
    const weaveView = new DataView(weaveS.buffer);
    let leftIntroducer = BigInt((weaveView.getUint32(0, true) % 0x7FFFFF) + 1);
    let rightIntroducer = BigInt((weaveView.getUint32(4, true) % 0x7FFFFF) + 1);
    while (leftIntroducer === rightIntroducer) {
      rightIntroducer = BigInt((Number(rightIntroducer) % 0x7FFFFF) + 1);
    }

    // step (50~600 质数)
    const step = P_50_600[stepS[0] % P_50_600.length];

    // KGM 与映射表
    const KGM = compact ? null : generateKGM(kgmS);
    const mappingTable = mode === 'DM' ? shuffleMap(DOUBLE_CODES, mapS) : shuffleMap(TRIPLE_CODES, mapS);

    return {
      eliminated, letters,
      addition, pointer, producer,
      leftIntroducer, rightIntroducer,
      step, KGM, mappingTable,
      mode, compact
    };
  }

  // 模逆元 (BigInt)
  function modInverseBig(a, m) {
    a = ((a % m) + m) % m;
    let [r0, r1] = [m, a];
    let [t0, t1] = [0n, 1n];
    while (r1 !== 0n) {
      const q = r0 / r1;
      [r0, r1] = [r1, r0 - q * r1];
      [t0, t1] = [t1, t0 - q * t1];
    }
    if (r0 !== 1n) throw new Error('逆元不存在');
    return ((t0 % m) + m) % m;
  }

  // ==================== 加密 ====================
  async function encryptE(plaintext, masterKeyHex, options = {}) {
    const { mode = 'TM', compact = true } = options;
    let salt = options.salt;
    if (!salt) salt = crypto.getRandomValues(new Uint8Array(16));
    if (masterKeyHex.length !== 64) throw new Error('主密钥须64位十六进制');
    if (plaintext === '') return { ciphertext: '', salt: bytesToHex(salt), mode, compact };

    const masterKeyBytes = hexToBytes(masterKeyHex);
    const params = await deriveAllParams(masterKeyBytes, salt, mode, compact);
    const { letters, addition, pointer, producer, leftIntroducer, rightIntroducer, step, KGM, mappingTable } = params;

    // 1. ascending (BigInt)
    const chars = [...plaintext];
    const A = chars.map((ch, idx) => {
      const uIndex = BigInt(ch.codePointAt(0));
      const idxBig = BigInt(idx + 1);
      return (uIndex * pointer + addition + producer * idxBig) % MOD;
    });

    if (A.length === 0) return { ciphertext: '', salt: bytesToHex(salt), mode, compact };

    // 2. weaving (异或链)
    const Ac = new Array(A.length);
    Ac[0] = A[0] ^ leftIntroducer;
    for (let i = 1; i < A.length; i++) Ac[i] = Ac[i - 1] ^ A[i];
    const Ad = new Array(Ac.length);
    const last = Ac.length - 1;
    Ad[last] = Ac[last] ^ rightIntroducer;
    for (let i = last; i > 0; i--) Ad[i - 1] = Ad[i] ^ Ac[i - 1];

    // 3. 固定6位24进制编码 -> r1 (长度 6*n)
    let r1 = Ad.map(val => toBase24Fixed6(val, letters)).join('');

    // 4. 插入 KGM (每次插入6字母)
    let r2 = r1;
    if (!compact) {
      r2 = '';
      let kgmIdx = 0;
      for (let i = 0; i < r1.length; i++) {
        r2 += r1[i];
        if ((i + 1) % step === 0) {
          r2 += KGM[kgmIdx % KGM.length];
          kgmIdx++;
        }
      }
    }

    // 5. 映射 (r2 长度必为6的倍数，无需填充)
    const blockSize = mode === 'DM' ? 2 : 3;
    let ciphertext = '';
    for (let i = 0; i < r2.length; i += blockSize) {
      ciphertext += mappingTable[r2.slice(i, i + blockSize)];
    }

    return { ciphertext, salt: bytesToHex(salt), mode, compact };
  }

  // ==================== 解密 ====================
  async function decryptE(ciphertext, masterKeyHex, saltHex, options = {}) {
    const { mode = 'TM', compact = true } = options;
    if (masterKeyHex.length !== 64) throw new Error('主密钥须64位十六进制');
    if (saltHex.length !== 32) throw new Error('盐值须32位十六进制');
    if (ciphertext === '') return '';

    const masterKeyBytes = hexToBytes(masterKeyHex);
    const salt = hexToBytes(saltHex);
    const params = await deriveAllParams(masterKeyBytes, salt, mode, compact);
    const { letters, addition, pointer, producer, leftIntroducer, rightIntroducer, step, KGM, mappingTable } = params;

    const invMap = {};
    for (const [k, v] of Object.entries(mappingTable)) {
      if (invMap[v]) throw new Error(`映射冲突: ${v}`);
      invMap[v] = k;
    }

    // 1. 密文 → 字母串 r2Full
    let remaining = ciphertext, r2Full = '';
    while (remaining.length > 0) {
      let matched = null;
      if (remaining.length >= 2) {
        const two = remaining.slice(0, 2);
        if (invMap[two]) matched = two;
      }
      if (!matched && invMap[remaining[0]]) matched = remaining[0];
      if (!matched) throw new Error(`无法解析密文 '${remaining[0]}'`);
      r2Full += invMap[matched];
      remaining = remaining.slice(matched.length);
    }

    // 2. 剥离 KGM (如果存在)，得到 r1
    let r1 = r2Full;
    if (!compact) {
      let r1test = '', kgmIdx = 0, i = 0, valid = true;
      while (i < r2Full.length) {
        r1test += r2Full[i++];
        if (r1test.length % step === 0 && i < r2Full.length) {
          const expected = KGM[kgmIdx % KGM.length];
          if (r2Full.substr(i, 6) !== expected) {
            valid = false;
            break;
          }
          i += 6;
          kgmIdx++;
        }
      }
      if (!valid) throw new Error('KGM 剥离失败，密钥或密文错误');
      r1 = r1test;
    }

    // 3. 将 r1 按 6 字母一组解码为 Ad 数组
    if (r1.length % 6 !== 0) throw new Error('解码错误：r1 长度不是6的倍数');
    const Ad = [];
    for (let i = 0; i < r1.length; i += 6) {
      Ad.push(fromBase24Fixed6(r1.slice(i, i + 6), letters));
    }

    // 4. 逆 weaving
    const len = Ad.length;
    const Ac = new Array(len);
    Ac[len - 1] = Ad[len - 1] ^ rightIntroducer;
    for (let i = len - 1; i > 0; i--) Ac[i - 1] = Ad[i] ^ Ad[i - 1];
    const A = new Array(len);
    A[0] = Ac[0] ^ leftIntroducer;
    for (let i = 1; i < len; i++) A[i] = Ac[i] ^ Ac[i - 1];

    // 5. 逆 ascending
    const pointerInv = modInverseBig(pointer, MOD);
    let plaintext = '';
    for (let idx = 0; idx < A.length; idx++) {
      const idxBig = BigInt(idx + 1);
      let t = (A[idx] - addition - producer * idxBig) % MOD;
      if (t < 0n) t += MOD;
      let uIndex = (t * pointerInv) % MOD;
      if (uIndex > 0x10FFFFn) throw new Error(`非法码点 ${uIndex}`);
      plaintext += String.fromCodePoint(Number(uIndex));
    }

    return plaintext;
  }

  // ==================== 用户友好接口 ====================
  async function easyEncryptE(plaintext, password, mode = 'TM', compact = true) {
    const pwdSalt = crypto.getRandomValues(new Uint8Array(16));
    const mk = await deriveMasterKeyFromPassword(password, pwdSalt);
    const { ciphertext, salt: innerSalt } = await encryptE(plaintext, mk, { mode, compact });
    return { pwdSalt: bytesToHex(pwdSalt), innerSalt, ciphertext, mode, compact };
  }

  async function easyDecryptE(packed, password) {
    const { pwdSalt, innerSalt, ciphertext, mode = 'TM', compact = true } = packed;
    const mk = await deriveMasterKeyFromPassword(password, hexToBytes(pwdSalt));
    return decryptE(ciphertext, mk, innerSalt, { mode, compact });
  }

  window.encryptE = encryptE;
  window.decryptE = decryptE;
  window.easyEncryptE = easyEncryptE;
  window.easyDecryptE = easyDecryptE;
})();