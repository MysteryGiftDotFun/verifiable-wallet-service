import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import { promises as fs } from 'fs';
import path from 'path';
import {
  Connection,
  Keypair,
  PublicKey,
  Transaction,
  sendAndConfirmTransaction,
} from '@solana/web3.js';
import {
  AuthorityType,
  createMint,
  getOrCreateAssociatedTokenAccount,
  mintTo,
  setAuthority,
  createTransferInstruction,
  getAssociatedTokenAddress,
  TOKEN_PROGRAM_ID,
  ASSOCIATED_TOKEN_PROGRAM_ID,
} from '@solana/spl-token';
import {
  createCreateMasterEditionV3Instruction,
  createCreateMetadataAccountV3Instruction,
} from '@metaplex-foundation/mpl-token-metadata';
import { DstackClient } from '@phala/dstack-sdk';

const app = express();
app.use(express.json());
app.use(cors());

// Internal Secret to protect this service
const SERVICE_SECRET = process.env.WALLET_SERVICE_SECRET || '';

// Middleware
const authMiddleware = (
  req: express.Request,
  res: express.Response,
  next: express.NextFunction
) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || authHeader !== `Bearer ${SERVICE_SECRET}`) {
    return res.status(401).json({ error: 'Unauthorized: Invalid Service Secret' });
  }
  next();
};

const VALID_PURPOSES = new Set(['vault', 'giveaway']);

// USDC Configuration
const USDC_MAINNET_MINT = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v';
const USDC_DEVNET_MINT = '4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU';
const USDC_DECIMALS = 6;
const LABELS_PATH =
  process.env.WALLET_LABELS_PATH || path.join(process.cwd(), 'data', 'wallet-labels.json');
const MAX_LABEL_LENGTH = 120;
const TOKEN_METADATA_PROGRAM_ID = new PublicKey('metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s');
const MAX_METADATA_NAME = 32;
const MAX_METADATA_SYMBOL = 10;

// Rate limiting configuration
const RATE_LIMIT_WINDOW_MS = 60 * 60 * 1000; // 1 hour
const RATE_LIMIT_MAX_REQUESTS = 10; // Max 10 USDC transfers per hour per IP
const DAILY_LIMIT_USD = 50000; // $50,000 daily aggregate limit

// In-memory rate limiting store (per-IP)
const rateLimitStore = new Map<string, { count: number; resetTime: number }>();

// Daily aggregate tracking
let dailyTransferredUsd = 0;
let dailyResetTime = Date.now() + 24 * 60 * 60 * 1000;

function resetDailyLimitIfNeeded(): void {
  const now = Date.now();
  if (now >= dailyResetTime) {
    dailyTransferredUsd = 0;
    dailyResetTime = now + 24 * 60 * 60 * 1000;
    console.log('[TEE] Daily transfer limit reset');
  }
}

function checkRateLimit(ip: string): { allowed: boolean; retryAfter?: number } {
  const now = Date.now();
  const record = rateLimitStore.get(ip);

  if (!record || now >= record.resetTime) {
    rateLimitStore.set(ip, { count: 1, resetTime: now + RATE_LIMIT_WINDOW_MS });
    return { allowed: true };
  }

  if (record.count >= RATE_LIMIT_MAX_REQUESTS) {
    const retryAfter = Math.ceil((record.resetTime - now) / 1000);
    return { allowed: false, retryAfter };
  }

  record.count += 1;
  return { allowed: true };
}

function getClientIp(req: express.Request): string {
  // Check X-Forwarded-For header (common for proxied requests)
  const forwarded = req.headers['x-forwarded-for'];
  if (typeof forwarded === 'string') {
    return forwarded.split(',')[0].trim();
  }
  if (Array.isArray(forwarded) && forwarded.length > 0) {
    return forwarded[0].split(',')[0].trim();
  }
  // Fallback to socket address
  return req.socket?.remoteAddress || 'unknown';
}

const rpcUrls = [
  process.env.HELIUS_RPC_URL,
  process.env.ALCHEMY_RPC_URL,
  process.env.SOLANA_RPC_URL,
].filter(Boolean) as string[];
let rpcIndex = 0;

function getRpcUrl(): string {
  if (rpcUrls.length === 0) {
    return 'https://api.devnet.solana.com';
  }
  const url = rpcUrls[rpcIndex % rpcUrls.length];
  rpcIndex += 1;
  return url;
}

function getVaultKeyId(purpose: string): string {
  return `mystery-gift-${purpose}-vault-v1`;
}

function getFallbackSeed(purpose: string): number {
  // Keep deterministic but distinct seeds for local dev.
  return purpose === 'giveaway' ? 3 : 2;
}

async function loadLabels(): Promise<Record<string, string>> {
  try {
    const data = await fs.readFile(LABELS_PATH, 'utf8');
    const parsed = JSON.parse(data) as Record<string, string>;
    const sanitized: Record<string, string> = {};
    for (const [key, value] of Object.entries(parsed)) {
      if (typeof value === 'string') {
        sanitized[key] = value;
      }
    }
    return sanitized;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      return {};
    }
    throw error;
  }
}

async function saveLabels(labels: Record<string, string>): Promise<void> {
  await fs.mkdir(path.dirname(LABELS_PATH), { recursive: true });
  await fs.writeFile(LABELS_PATH, JSON.stringify(labels, null, 2), 'utf8');
}

async function withRetry<T>(operation: () => Promise<T>, label: string, attempts = 3): Promise<T> {
  let lastError: unknown = null;
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    try {
      return await operation();
    } catch (error) {
      lastError = error;
      const delayMs = Math.min(1000 * 2 ** (attempt - 1), 8000);
      await new Promise((resolve) => setTimeout(resolve, delayMs));
    }
  }

  throw lastError instanceof Error
    ? lastError
    : new Error(`Operation failed after ${attempts} attempts: ${label}`);
}

/**
 * Derives the secure vault keypair from the TEE environment.
 * In local dev (simulated), it uses a deterministic fallback seed.
 */
async function getVaultKey(purpose: string = 'vault'): Promise<Keypair> {
  try {
    const keyId = getVaultKeyId(purpose);

    // Attempt TEE derivation using DstackClient
    const dstack = new DstackClient();
    const keyResponse = await dstack.getKey('/', keyId);

    // Ensure we have 32 bytes for the seed
    const seed = keyResponse.key.subarray(0, 32);
    return Keypair.fromSeed(seed);
  } catch (e) {
    // Strict check: If we claim to be in a TEE (dev or prod), we MUST NOT fallback.
    if (process.env.PHALA_TEE === 'true') {
      console.error('[TEE] CRITICAL: Failed to derive key in TEE environment!');
      throw e;
    }

    console.warn(
      '[TEE] Derivation failed (Simulated/Local Mode). Using deterministic fallback key.'
    );

    // Fallback deterministic key for local testing only
    // Seed: 32 bytes of a purpose-specific value.
    const fallbackSeed = new Uint8Array(32).fill(getFallbackSeed(purpose));
    return Keypair.fromSeed(fallbackSeed);
  }
}

async function createMetadataAccounts(
  connection: Connection,
  payer: Keypair,
  mint: PublicKey,
  uri: string,
  name: string,
  symbol: string
): Promise<void> {
  const metadataPda = PublicKey.findProgramAddressSync(
    [Buffer.from('metadata'), TOKEN_METADATA_PROGRAM_ID.toBuffer(), mint.toBuffer()],
    TOKEN_METADATA_PROGRAM_ID
  )[0];

  const masterEditionPda = PublicKey.findProgramAddressSync(
    [
      Buffer.from('metadata'),
      TOKEN_METADATA_PROGRAM_ID.toBuffer(),
      mint.toBuffer(),
      Buffer.from('edition'),
    ],
    TOKEN_METADATA_PROGRAM_ID
  )[0];

  const metadataIx = createCreateMetadataAccountV3Instruction(
    {
      metadata: metadataPda,
      mint,
      mintAuthority: payer.publicKey,
      payer: payer.publicKey,
      updateAuthority: payer.publicKey,
    },
    {
      createMetadataAccountArgsV3: {
        data: {
          name: name.slice(0, MAX_METADATA_NAME),
          symbol: symbol.slice(0, MAX_METADATA_SYMBOL),
          uri,
          sellerFeeBasisPoints: 0,
          creators: null,
          collection: null,
          uses: null,
        },
        isMutable: true,
        collectionDetails: null,
      },
    }
  );

  const masterEditionIx = createCreateMasterEditionV3Instruction(
    {
      edition: masterEditionPda,
      mint,
      updateAuthority: payer.publicKey,
      mintAuthority: payer.publicKey,
      payer: payer.publicKey,
      metadata: metadataPda,
    },
    { createMasterEditionArgs: { maxSupply: 0 } }
  );

  const tx = new Transaction().add(metadataIx, masterEditionIx);
  await withRetry(
    () => sendAndConfirmTransaction(connection, tx, [payer], { commitment: 'confirmed' }),
    'create metadata accounts'
  );
}

app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    service: 'verifiable-wallet-service',
    version: process.env.APP_VERSION || '0.1.0',
    environment: process.env.APP_ENVIRONMENT || 'development',
    tee: process.env.PHALA_TEE ? 'active' : 'simulated',
    timestamp: new Date().toISOString(),
  });
});

app.get('/', (_req, res) => {
  res.redirect('/dashboard');
});

/**
 * Returns the Public Key of the Vault.
 * Marketplace API uses this to build transactions.
 */
app.get('/public-key', authMiddleware, async (req, res) => {
  try {
    const purpose = (req.query?.purpose as string) || 'vault';
    if (!VALID_PURPOSES.has(purpose)) {
      return res.status(400).json({ error: 'Invalid purpose' });
    }

    const keypair = await getVaultKey(purpose);
    res.json({
      publicKey: keypair.publicKey.toBase58(),
    });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/wallets', authMiddleware, async (_req, res) => {
  try {
    const labels = await loadLabels();
    const purposes = Array.from(VALID_PURPOSES.values());
    const wallets = await Promise.all(
      purposes.map(async (purpose) => {
        const keypair = await getVaultKey(purpose);
        return {
          purpose,
          publicKey: keypair.publicKey.toBase58(),
          label: labels[purpose] || '',
        };
      })
    );

    res.json({ wallets });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/wallets/labels', authMiddleware, async (req, res) => {
  try {
    const { purpose, label } = req.body as { purpose?: string; label?: string };
    if (!purpose || !VALID_PURPOSES.has(purpose)) {
      return res.status(400).json({ error: 'Invalid purpose' });
    }
    if (label !== undefined && typeof label !== 'string') {
      return res.status(400).json({ error: 'Label must be a string' });
    }

    const sanitizedLabel = (label || '').trim();
    if (sanitizedLabel.length > MAX_LABEL_LENGTH) {
      return res.status(400).json({ error: `Label too long (max ${MAX_LABEL_LENGTH})` });
    }

    const labels = await loadLabels();
    if (!sanitizedLabel) {
      delete labels[purpose];
    } else {
      labels[purpose] = sanitizedLabel;
    }

    await saveLabels(labels);
    res.json({ success: true, labels });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

/**
 * SPECIFICATION
 * - Purpose: Mint an NFT using the TEE vault key and return mint details.
 * - Inputs: name, symbol, uri, recipient (optional), purpose (query).
 * - Behavior: Creates mint + ATA + metadata + master edition, mints 1 token, locks mint authority.
 * - Errors: Validates required fields, uses service secret auth, returns HTTP 4xx/5xx.
 */
app.post('/mint-nft', authMiddleware, async (req, res) => {
  try {
    const { name, symbol, uri, recipient } = req.body as {
      name?: string;
      symbol?: string;
      uri?: string;
      recipient?: string;
    };
    const purpose = (req.query?.purpose as string) || 'vault';

    if (!VALID_PURPOSES.has(purpose)) {
      return res.status(400).json({ error: 'Invalid purpose' });
    }

    if (!name || !symbol || !uri) {
      return res.status(400).json({ error: 'name, symbol, and uri are required' });
    }

    const sanitizedName = String(name).trim();
    const sanitizedSymbol = String(symbol).trim();
    const sanitizedUri = String(uri).trim();

    if (!sanitizedName || !sanitizedSymbol || !sanitizedUri) {
      return res.status(400).json({ error: 'name, symbol, and uri must be non-empty' });
    }

    const connection = new Connection(getRpcUrl(), 'confirmed');
    const keypair = await getVaultKey(purpose);
    const recipientKey = recipient ? new PublicKey(recipient) : keypair.publicKey;

    const mint = await withRetry(
      () => createMint(connection, keypair, keypair.publicKey, keypair.publicKey, 0),
      'create mint'
    );

    const tokenAccount = await withRetry(
      () => getOrCreateAssociatedTokenAccount(connection, keypair, mint, recipientKey),
      'get associated token account'
    );

    await withRetry(
      () => mintTo(connection, keypair, mint, tokenAccount.address, keypair, 1),
      'mint token'
    );

    await createMetadataAccounts(
      connection,
      keypair,
      mint,
      sanitizedUri,
      sanitizedName,
      sanitizedSymbol
    );

    res.json({
      success: true,
      mint: mint.toBase58(),
      recipient: recipientKey.toBase58(),
    });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

/**
 * Transfer an NFT using the vault key inside TEE.
 * Body: { mint: string; recipient: string; amount?: number }
 */
app.post('/transfer-nft', authMiddleware, async (req, res) => {
  try {
    const { mint, recipient, amount } = req.body as {
      mint?: string;
      recipient?: string;
      amount?: number;
    };

    if (!mint || !recipient) {
      return res.status(400).json({ error: 'mint and recipient are required' });
    }

    const connection = new Connection(getRpcUrl(), 'confirmed');
    const vaultKeypair = await getVaultKey('vault');
    const mintKey = new PublicKey(mint);
    const recipientKey = new PublicKey(recipient);
    const transferAmount = amount && amount > 0 ? amount : 1;

    const sourceAta = await withRetry(
      () =>
        getOrCreateAssociatedTokenAccount(
          connection,
          vaultKeypair,
          mintKey,
          vaultKeypair.publicKey
        ),
      'get source ATA'
    );
    const destAta = await withRetry(
      () => getOrCreateAssociatedTokenAccount(connection, vaultKeypair, mintKey, recipientKey),
      'get destination ATA'
    );

    const sig = await withRetry(
      () =>
        sendAndConfirmTransaction(
          connection,
          new Transaction().add(
            createTransferInstruction(
              sourceAta.address,
              destAta.address,
              vaultKeypair.publicKey,
              transferAmount
            )
          ),
          [vaultKeypair],
          { commitment: 'confirmed' }
        ),
      'transfer nft'
    );

    res.json({ success: true, signature: sig });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

/**
 * Transfer USDC from vault to a recipient.
 * Used for automated buyback payouts.
 *
 * Body: { recipient: string; amountUsd: number; memo?: string }
 */
app.post('/transfer-usdc', authMiddleware, async (req, res) => {
  try {
    // Rate limiting check
    const clientIp = getClientIp(req);
    const rateCheck = checkRateLimit(clientIp);
    if (!rateCheck.allowed) {
      console.warn(`[TEE] Rate limit exceeded for IP: ${clientIp}`);
      return res.status(429).json({
        error: 'Too many transfer requests. Please try again later.',
        retryAfter: rateCheck.retryAfter,
      });
    }

    // Daily aggregate limit check
    resetDailyLimitIfNeeded();

    const { recipient, amountUsd, memo } = req.body as {
      recipient?: string;
      amountUsd?: number;
      memo?: string;
    };

    if (!recipient) {
      return res.status(400).json({ error: 'recipient is required' });
    }

    if (!amountUsd || amountUsd <= 0) {
      return res.status(400).json({ error: 'amountUsd must be a positive number' });
    }

    // Safety limit: max $10,000 per transfer to prevent catastrophic errors
    const MAX_TRANSFER_USD = 10000;
    if (amountUsd > MAX_TRANSFER_USD) {
      return res.status(400).json({
        error: `Amount exceeds maximum single transfer limit of $${MAX_TRANSFER_USD}`,
      });
    }

    // Check daily aggregate limit
    if (dailyTransferredUsd + amountUsd > DAILY_LIMIT_USD) {
      console.warn(`[TEE] Daily limit would be exceeded: current=$${dailyTransferredUsd}, requested=$${amountUsd}, limit=$${DAILY_LIMIT_USD}`);
      return res.status(400).json({
        error: `Daily transfer limit would be exceeded. Limit: $${DAILY_LIMIT_USD}, Used: $${dailyTransferredUsd.toFixed(2)}, Requested: $${amountUsd}`,
        dailyUsed: dailyTransferredUsd,
        dailyLimit: DAILY_LIMIT_USD,
      });
    }

    const connection = new Connection(getRpcUrl(), 'confirmed');
    const vaultKeypair = await getVaultKey('vault');

    // Determine USDC mint based on network
    const rpcUrl = getRpcUrl();
    const isMainnet = rpcUrl.includes('mainnet');
    const usdcMint = new PublicKey(isMainnet ? USDC_MAINNET_MINT : USDC_DEVNET_MINT);

    const recipientKey = new PublicKey(recipient);

    // Convert USD to USDC amount (6 decimals)
    const amountRaw = BigInt(Math.floor(amountUsd * Math.pow(10, USDC_DECIMALS)));

    console.log(`[TEE] Initiating USDC transfer: $${amountUsd} to ${recipient}`);
    if (memo) {
      console.log(`[TEE] Memo: ${memo}`);
    }

    // Get source ATA (vault's USDC account)
    const sourceAta = await getAssociatedTokenAddress(usdcMint, vaultKeypair.publicKey);

    // Check vault USDC balance
    try {
      const balance = await connection.getTokenAccountBalance(sourceAta);
      const vaultBalance = Number(balance.value.amount) / Math.pow(10, USDC_DECIMALS);
      if (vaultBalance < amountUsd) {
        return res.status(400).json({
          error: `Insufficient USDC balance. Vault has $${vaultBalance.toFixed(2)}, requested $${amountUsd}`,
          vaultBalance,
        });
      }
      console.log(`[TEE] Vault USDC balance: $${vaultBalance.toFixed(2)}`);
    } catch (e) {
      return res.status(400).json({
        error: 'Vault has no USDC token account',
      });
    }

    // Get or create destination ATA
    const destAta = await withRetry(
      () => getOrCreateAssociatedTokenAccount(connection, vaultKeypair, usdcMint, recipientKey),
      'get destination USDC ATA'
    );

    // Build and send transfer transaction
    const sig = await withRetry(
      () =>
        sendAndConfirmTransaction(
          connection,
          new Transaction().add(
            createTransferInstruction(
              sourceAta,
              destAta.address,
              vaultKeypair.publicKey,
              amountRaw
            )
          ),
          [vaultKeypair],
          { commitment: 'confirmed' }
        ),
      'transfer USDC'
    );

    console.log(`[TEE] USDC transfer completed: ${sig}`);

    // Update daily aggregate after successful transfer
    dailyTransferredUsd += amountUsd;
    console.log(`[TEE] Daily transferred total: $${dailyTransferredUsd.toFixed(2)} / $${DAILY_LIMIT_USD}`);

    res.json({
      success: true,
      signature: sig,
      amount: amountUsd,
      recipient,
      memo: memo || null,
    });
  } catch (error: any) {
    console.error('[TEE] USDC transfer failed:', error);
    res.status(500).json({ error: error.message });
  }
});

/**
 * Get vault USDC balance
 */
app.get('/usdc-balance', authMiddleware, async (req, res) => {
  try {
    const purpose = (req.query?.purpose as string) || 'vault';
    if (!VALID_PURPOSES.has(purpose)) {
      return res.status(400).json({ error: 'Invalid purpose' });
    }

    const connection = new Connection(getRpcUrl(), 'confirmed');
    const keypair = await getVaultKey(purpose);

    // Determine USDC mint based on network
    const rpcUrl = getRpcUrl();
    const isMainnet = rpcUrl.includes('mainnet');
    const usdcMint = new PublicKey(isMainnet ? USDC_MAINNET_MINT : USDC_DEVNET_MINT);

    const ata = await getAssociatedTokenAddress(usdcMint, keypair.publicKey);

    try {
      const balance = await connection.getTokenAccountBalance(ata);
      const usdBalance = Number(balance.value.amount) / Math.pow(10, USDC_DECIMALS);

      res.json({
        success: true,
        balance: usdBalance,
        balanceRaw: balance.value.amount,
        decimals: USDC_DECIMALS,
        usdcMint: usdcMint.toBase58(),
        wallet: keypair.publicKey.toBase58(),
        tokenAccount: ata.toBase58(),
      });
    } catch (e) {
      // No USDC account exists
      res.json({
        success: true,
        balance: 0,
        balanceRaw: '0',
        decimals: USDC_DECIMALS,
        usdcMint: usdcMint.toBase58(),
        wallet: keypair.publicKey.toBase58(),
        tokenAccount: null,
        message: 'No USDC token account exists for this wallet',
      });
    }
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

function getDashboardHtml(): string {
  const version = process.env.APP_VERSION || '0.1.0';
  const environment = process.env.APP_ENVIRONMENT || 'development';
  const teeStatus = process.env.PHALA_TEE ? 'active' : 'simulated';
  const envBadgeClass = environment === 'production' ? 'production' : 'development';
  const envBadgeText = environment === 'production' ? 'PROD' : 'DEV';

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
  <title>WALLET SERVICE | MYSTERY GIFT</title>

  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Sometype+Mono:ital,wght@0,400;0,500;0,600;0,700;1,400&display=swap" rel="stylesheet">

  <script src="https://code.iconify.design/iconify-icon/1.0.7/iconify-icon.min.js"></script>

  <style>
    :root {
      --bg: #09090b;
      --panel-bg: rgba(20, 20, 23, 0.75);
      --panel-border: rgba(255, 255, 255, 0.08);
      --text-main: #FAFAFA;
      --text-muted: #A1A1AA;
      --accent: #7DD3FC;
      --accent-glow: rgba(125, 211, 252, 0.2);
      --success: #34D399;
      --error: #F87171;
      --info: #A5B4FC;
      --font: 'Sometype Mono', monospace;
    }
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: var(--font); background-color: var(--bg); color: var(--text-main); height: 100vh; width: 100vw; overflow: hidden; }

    .layout { display: grid; grid-template-columns: 1fr 450px; height: 100vh; width: 100%; overflow: hidden; }

    .hero {
      position: relative;
      display: flex;
      flex-direction: column;
      justify-content: flex-end;
      align-items: center;
      overflow: hidden;
      background-color: var(--bg);
      background-image: url("data:image/svg+xml,%3Csvg width='400' height='400' viewBox='0 0 400 400' xmlns='http://www.w3.org/2000/svg'%3E%3Cstyle%3Etext { font-family: monospace; fill: %23ffffff; opacity: 0.02; font-weight: bold; user-select: none; }%3C/style%3E%3Ctext x='50' y='80' font-size='120' transform='rotate(15 50,80)'%3E?%3C/text%3E%3Ctext x='300' y='150' font-size='80' transform='rotate(-20 300,150)'%3E?%3C/text%3E%3Ctext x='150' y='300' font-size='160' transform='rotate(10 150,300)'%3E?%3C/text%3E%3Ctext x='350' y='350' font-size='60' transform='rotate(30 350,350)'%3E?%3C/text%3E%3Ctext x='100' y='200' font-size='40' opacity='0.04' transform='rotate(-45 100,200)'%3E?%3C/text%3E%3Ctext x='250' y='50' font-size='90' transform='rotate(5 250,50)'%3E?%3C/text%3E%3Ctext x='20' y='380' font-size='70' transform='rotate(-15 20,380)'%3E?%3C/text%3E%3C/svg%3E");
      transition: background-position 0.1s linear;
    }

    .hero-info { position: absolute; bottom: 3rem; left: 3.5rem; z-index: 20; max-width: 600px; }
    h1 { font-size: 3.5rem; font-weight: 700; line-height: 0.9; letter-spacing: -0.04em; text-transform: uppercase; color: var(--text-main); margin-bottom: 0.8rem; text-shadow: 0 10px 30px rgba(0,0,0,0.8); }
    .subtitle { font-size: 1rem; color: var(--accent); font-weight: 600; letter-spacing: 0.2em; text-transform: uppercase; display: flex; align-items: center; gap: 0.5rem; }
    .subtitle::before { content: ''; display: block; width: 40px; height: 2px; background: var(--accent); }

    .version-tag { position: absolute; bottom: 2rem; right: 2rem; font-size: 0.75rem; color: var(--text-muted); opacity: 0.5; font-weight: 600; z-index: 20; display: flex; align-items: center; gap: 0.5rem; }
    .env-badge { display: inline-flex; align-items: center; padding: 0.2rem 0.5rem; border-radius: 4px; font-size: 0.65rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; }
    .env-badge.production { background: rgba(52, 211, 153, 0.2); color: #34D399; }
    .env-badge.development { background: rgba(255, 149, 0, 0.2); color: #FF9500; }
    .tee-badge { padding: 0.2rem 0.5rem; border-radius: 4px; font-size: 0.65rem; font-weight: 700; text-transform: uppercase; }
    .tee-badge.active { background: rgba(52, 211, 153, 0.2); color: #34D399; }
    .tee-badge.simulated { background: rgba(255, 149, 0, 0.2); color: #FF9500; }

    .miss-container { position: absolute; bottom: -80px; left: 0; right: 0; z-index: 10; height: 90vh; display: flex; align-items: flex-end; justify-content: center; transition: transform 0.1s linear; }
    .miss-img { height: 100%; max-height: 900px; object-fit: contain; object-position: bottom center; filter: drop-shadow(0 0 60px rgba(0,0,0,0.6)); transform: scaleX(-1); }

    .panel { background: var(--panel-bg); border-left: 1px solid var(--panel-border); backdrop-filter: blur(30px); -webkit-backdrop-filter: blur(30px); display: flex; flex-direction: column; position: relative; z-index: 50; height: 100vh; }

    .tabs { display: flex; gap: 0.2rem; padding: 0.5rem 2rem 0; margin-bottom: 1.5rem; border-bottom: 1px solid var(--panel-border); flex-shrink: 0; overflow-x: auto; }
    .tab-btn { padding: 0.8rem 1.2rem; background: transparent; color: var(--text-muted); border: none; font-family: var(--font); font-weight: 500; font-size: 0.85rem; cursor: pointer; border-bottom: 2px solid transparent; transition: all 0.2s; white-space: nowrap; }
    .tab-btn.active { color: var(--text-main); border-bottom-color: var(--accent); }
    .tab-btn:hover:not(.active) { color: var(--text-main); }

    .content-wrapper { flex: 1; overflow-y: auto; padding: 0 1.5rem 1.5rem; display: flex; flex-direction: column; }
    .content-wrapper::-webkit-scrollbar { width: 4px; }
    .content-wrapper::-webkit-scrollbar-track { background: transparent; }
    .content-wrapper::-webkit-scrollbar-thumb { background: rgba(255, 255, 255, 0.1); border-radius: 4px; }

    .tab-view { display: none; width: 100%; }
    .tab-view.active { display: block; animation: fadeIn 0.3s ease; }

    .card { background: rgba(0, 0, 0, 0.3); border: 1px solid var(--panel-border); border-radius: 12px; padding: 1.2rem; margin-bottom: 1.5rem; }
    .card-label { font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase; margin-bottom: 0.8rem; display: block; font-weight: 600; letter-spacing: 0.05em; }

    .sleek-input { width: 100%; padding: 0.9rem; background: rgba(0,0,0,0.4); color: var(--text-main); border: 1px solid var(--panel-border); border-radius: 8px; font-family: var(--font); font-size: 0.9rem; margin-bottom: 1rem; outline: none; transition: all 0.2s; }
    .sleek-input:focus { border-color: var(--accent); background-color: rgba(0,0,0,0.6); }

    .wallet-card { background: rgba(125, 211, 252, 0.05); border: 1px solid rgba(125, 211, 252, 0.2); border-radius: 12px; padding: 1rem; margin-bottom: 1rem; }
    .wallet-purpose { font-weight: 600; color: var(--accent); margin-bottom: 0.5rem; text-transform: uppercase; font-size: 0.8rem; }
    .wallet-address { font-family: monospace; font-size: 0.7rem; color: var(--text-muted); word-break: break-all; margin-bottom: 0.75rem; }

    .endpoint { background: rgba(255,255,255,0.03); border: 1px solid var(--panel-border); border-radius: 8px; padding: 0.8rem; margin-bottom: 0.75rem; }
    .method { display: inline-block; padding: 0.2rem 0.5rem; border-radius: 4px; font-size: 0.7rem; font-weight: 700; margin-right: 0.5rem; }
    .method.get { background: #34D399; color: #000; }
    .method.post { background: #3B82F6; color: #fff; }
    .path { font-family: monospace; color: var(--accent); font-size: 0.85rem; }
    .desc { color: var(--text-muted); font-size: 0.75rem; margin-top: 0.4rem; }

    .std-btn { width: 100%; padding: 0.9rem; background: rgba(255,255,255,0.05); border: 1px solid var(--panel-border); border-radius: 8px; color: var(--text-main); font-family: var(--font); font-weight: 600; cursor: pointer; transition: all 0.2s; }
    .std-btn:hover { background: rgba(255,255,255,0.1); border-color: var(--text-main); }
    .std-btn.primary { background: var(--accent); color: #000; border: none; }
    .std-btn.primary:hover { opacity: 0.9; }

    .status-msg { font-size: 0.8rem; padding: 0.5rem 0; }
    .status-msg.success { color: var(--success); }
    .status-msg.error { color: var(--error); }

    .console-bar { background: #050505; border-top: 1px solid var(--panel-border); color: var(--text-muted); font-family: monospace; font-size: 0.75rem; cursor: pointer; transition: height 0.3s ease; height: 34px; overflow: hidden; flex-shrink: 0; }
    .console-header { padding: 0.6rem 2rem; display: flex; align-items: center; gap: 0.5rem; background: rgba(255,255,255,0.02); }
    .console-indicator { width: 6px; height: 6px; border-radius: 50%; background: var(--success); box-shadow: 0 0 5px var(--success); }
    .console-content { padding: 0 2rem 1rem; overflow-y: auto; height: 160px; }
    .console-bar.expanded { height: 200px; }

    .legal-footer { padding: 1rem 2rem; font-size: 0.7rem; color: var(--text-muted); text-align: center; border-top: 1px solid var(--panel-border); background: var(--panel-bg); flex-shrink: 0; }
    .legal-footer a { color: var(--text-muted); }

    .log-line { margin-bottom: 4px; }
    .log-success { color: var(--success); }
    .log-error { color: var(--error); }
    .log-info { color: var(--info); }

    @media (max-width: 1024px) {
      .layout { grid-template-columns: 1fr; grid-template-rows: auto 1fr; height: auto; overflow-y: auto; }
      .hero { height: 50vh; min-height: 400px; border-bottom: 1px solid var(--panel-border); justify-content: flex-end; }
      .miss-img { max-height: 450px; }
      .hero-info { top: auto; bottom: 2rem; left: 1.5rem; max-width: 80%; }
      h1 { font-size: 2rem; }
      .panel { min-height: 60vh; height: auto; overflow: visible; }
      .content-wrapper { padding: 0 1.5rem 2rem; }
      .console-bar { display: none; }
    }

    @keyframes fadeIn { from { opacity: 0; transform: translateY(5px); } to { opacity: 1; transform: translateY(0); } }
  </style>
</head>
<body>
  <div class="layout">
    <!-- Hero -->
    <div class="hero" id="hero-section">
      <div class="hero-info">
        <h1>VERIFIABLE<br>WALLET<br>SERVICE</h1>
        <div class="subtitle">TEE-SECURED VAULT</div>
      </div>

      <div class="miss-container" id="miss-container">
        <img src="https://cdn.mysterygift.fun/miss.png" class="miss-img" alt="Miss">
      </div>

      <div class="version-tag">
        v${version}
        <span class="env-badge ${envBadgeClass}">${envBadgeText}</span>
        <span class="tee-badge ${teeStatus}">${teeStatus.toUpperCase()}</span>
      </div>
    </div>

    <!-- Panel -->
    <div class="panel">
      <!-- Tabs -->
      <div class="tabs">
        <button class="tab-btn active" onclick="nav('wallets')" id="t-wallets">WALLETS</button>
        <button class="tab-btn" onclick="nav('guide')" id="t-guide">GUIDE</button>
        <button class="tab-btn" onclick="nav('api')" id="t-api">API</button>
        <button class="tab-btn" onclick="nav('info')" id="t-info">INFO</button>
      </div>

      <!-- Content -->
      <div class="content-wrapper">

        <!-- WALLETS -->
        <div id="v-wallets" class="tab-view active">
          <div class="card">
            <span class="card-label">Authentication</span>
            <input type="password" class="sleek-input" id="secret-input" placeholder="Enter service secret" style="margin-bottom:0.5rem;">
            <div id="status-msg" class="status-msg"></div>
            <div style="display: flex; gap: 0.5rem;">
              <button class="std-btn primary" onclick="loadWallets()" style="flex:1;">Load Wallets</button>
              <button class="std-btn" onclick="saveLabels()" style="flex:1;">Save Labels</button>
            </div>
          </div>

          <div id="wallets-container">
            <p style="font-size:0.8rem; color:var(--text-muted); text-align:center; padding:2rem 0;">
              Enter your service secret and click "Load Wallets" to view TEE-derived wallet addresses.
            </p>
          </div>
        </div>

        <!-- GUIDE -->
        <div id="v-guide" class="tab-view">
          <div class="card">
            <span class="card-label">How It Works</span>
            <div style="font-size:0.85rem; color:var(--text-muted); line-height:1.8;">
              <div style="margin-bottom:0.8rem; display:flex; gap:10px;">
                <span style="color:var(--accent); font-weight:700;">1.</span>
                <span>Wallet keys are derived inside Intel TDX TEE</span>
              </div>
              <div style="margin-bottom:0.8rem; display:flex; gap:10px;">
                <span style="color:var(--accent); font-weight:700;">2.</span>
                <span>Private keys never leave the secure enclave</span>
              </div>
              <div style="margin-bottom:0.8rem; display:flex; gap:10px;">
                <span style="color:var(--accent); font-weight:700;">3.</span>
                <span>Transactions are signed inside TEE</span>
              </div>
              <div style="display:flex; gap:10px;">
                <span style="color:var(--accent); font-weight:700;">4.</span>
                <span>Attestation proofs verify integrity</span>
              </div>
            </div>
          </div>

          <div class="card">
            <span class="card-label">Wallet Purposes</span>
            <div style="font-size:0.85rem; color:var(--text-muted); line-height:1.6;">
              <div style="margin-bottom:0.5rem;"><strong style="color:var(--accent);">vault</strong> - Main NFT vault for marketplace</div>
              <div><strong style="color:var(--accent);">giveaway</strong> - Daily raffle prize distribution</div>
            </div>
          </div>
        </div>

        <!-- API -->
        <div id="v-api" class="tab-view">
          <div class="card">
            <span class="card-label">API Endpoints</span>

            <div class="endpoint">
              <span class="method get">GET</span>
              <span class="path">/health</span>
              <p class="desc">Health check with TEE status</p>
            </div>

            <div class="endpoint">
              <span class="method get">GET</span>
              <span class="path">/public-key</span>
              <p class="desc">Get vault public key. Query: ?purpose=vault|giveaway</p>
            </div>

            <div class="endpoint">
              <span class="method get">GET</span>
              <span class="path">/wallets</span>
              <p class="desc">List all TEE-derived wallets (auth required)</p>
            </div>

            <div class="endpoint">
              <span class="method post">POST</span>
              <span class="path">/mint-nft</span>
              <p class="desc">Mint NFT using vault key (auth required)</p>
            </div>

            <div class="endpoint">
              <span class="method post">POST</span>
              <span class="path">/transfer-nft</span>
              <p class="desc">Transfer NFT from vault (auth required)</p>
            </div>

            <div class="endpoint">
              <span class="method post">POST</span>
              <span class="path">/sign-transaction</span>
              <p class="desc">Sign transaction in TEE (auth required)</p>
            </div>

            <div class="endpoint">
              <span class="method post">POST</span>
              <span class="path">/transfer-usdc</span>
              <p class="desc">Transfer USDC from vault for buyback payouts (auth required)</p>
            </div>

            <div class="endpoint">
              <span class="method get">GET</span>
              <span class="path">/usdc-balance</span>
              <p class="desc">Get vault USDC balance (auth required)</p>
            </div>
          </div>
        </div>

        <!-- INFO -->
        <div id="v-info" class="tab-view">
          <div class="card">
            <span class="card-label">Service Information</span>
            <p style="font-size:0.85rem; color:var(--text-muted); line-height:1.5; margin-bottom: 1rem;">
              TEE-secured wallet service for NFT vault management. Keys are derived and stored inside Intel TDX hardware enclave.
            </p>
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 0.75rem;">
              <div style="background: rgba(0,0,0,0.3); padding: 0.75rem; border-radius: 8px;">
                <div style="font-size: 0.7rem; color: var(--text-muted); margin-bottom: 0.25rem;">VERSION</div>
                <div style="font-size: 0.9rem; font-weight: 600;">${version}</div>
              </div>
              <div style="background: rgba(0,0,0,0.3); padding: 0.75rem; border-radius: 8px;">
                <div style="font-size: 0.7rem; color: var(--text-muted); margin-bottom: 0.25rem;">TEE STATUS</div>
                <div style="font-size: 0.9rem; font-weight: 600; color: ${teeStatus === 'active' ? 'var(--success)' : '#FF9500'};">${teeStatus.toUpperCase()}</div>
              </div>
            </div>
          </div>

          <div class="card">
            <span class="card-label">Security</span>
            <p style="font-size:0.85rem; color:var(--text-muted); line-height:1.5;">
              <strong style="color:var(--text-main);">Intel TDX</strong> - Hardware-backed trusted execution<br>
              <strong style="color:var(--text-main);">Phala Network</strong> - Decentralized TEE infrastructure<br>
              <strong style="color:var(--text-main);">Remote Attestation</strong> - Verifiable enclave integrity
            </p>
          </div>

          <div class="card">
            <span class="card-label">Links</span>
            <a href="https://github.com/mysterygift/mystery-gift" target="_blank" style="text-decoration:none">
              <button class="std-btn" style="margin-bottom:0.8rem;">
                <iconify-icon icon="ph:github-logo-fill" style="vertical-align:text-bottom; margin-right:4px;"></iconify-icon> View Source Code
              </button>
            </a>
            <a href="https://mysterygift.fun" target="_blank" style="text-decoration:none; display:block;">
              <button class="std-btn">
                <iconify-icon icon="ph:globe" style="vertical-align:text-bottom; margin-right:4px;"></iconify-icon>
                Mystery Gift Platform
              </button>
            </a>
          </div>
        </div>

      </div>

      <!-- Console Footer -->
      <div class="console-bar" id="console-bar" onclick="toggleConsole()">
        <div class="console-header">
          <div class="console-indicator" id="status-dot"></div>
          <span id="status-text">System Ready</span>
          <div style="flex:1"></div>
          <iconify-icon icon="ph:caret-up-bold" id="console-chevron"></iconify-icon>
        </div>
        <div class="console-content" id="console">
          <div class="log-line">> Wallet Service v${version}</div>
          <div class="log-line">> Environment: ${environment}</div>
          <div class="log-line">> TEE: ${teeStatus}</div>
        </div>
      </div>

      <div class="legal-footer">
        &copy; 2026 MYSTERY GIFT &bull; <a href="https://mysterygift.fun/terms">Terms</a> &bull; <a href="https://mysterygift.fun/privacy">Privacy</a> &bull; <a href="https://x.com/mysterygift_fun" target="_blank">X</a>
      </div>
    </div>
  </div>

  <script>
    // Tab Navigation
    function nav(tab) {
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.tab-view').forEach(v => v.classList.remove('active'));
      document.getElementById('t-'+tab).classList.add('active');
      document.getElementById('v-'+tab).classList.add('active');
    }

    // Console
    let consoleExpanded = false;
    function toggleConsole() {
      consoleExpanded = !consoleExpanded;
      const bar = document.getElementById('console-bar');
      const chevron = document.getElementById('console-chevron');
      bar.classList.toggle('expanded', consoleExpanded);
      chevron.setAttribute('icon', consoleExpanded ? 'ph:caret-down-bold' : 'ph:caret-up-bold');
    }

    function log(msg, type='info') {
      const t = document.getElementById('console');
      const d = document.createElement('div');
      d.className = 'log-line ' + (type==='success'?'log-success':type==='error'?'log-error':'log-info');
      d.innerText = '> ' + msg;
      t.appendChild(d);
      t.scrollTop = t.scrollHeight;
      document.getElementById('status-text').innerText = msg;
    }

    // Hero parallax
    const hero = document.getElementById('hero-section');
    const miss = document.getElementById('miss-container');
    if(hero && miss && window.innerWidth > 1024) {
      hero.addEventListener('mousemove', (e) => {
        const { width, height } = hero.getBoundingClientRect();
        const x = (e.clientX / width - 0.5) * 20;
        const y = (e.clientY / height - 0.5) * 20;
        hero.style.backgroundPosition = 'calc(50% - ' + x + 'px) calc(50% - ' + y + 'px)';
        miss.style.transform = 'translate(' + (x*0.5) + 'px, ' + (y*0.5) + 'px)';
      });
    }

    // Wallet Management
    const secretInput = document.getElementById('secret-input');
    const statusMsg = document.getElementById('status-msg');
    const walletsContainer = document.getElementById('wallets-container');

    // Load saved secret
    const savedSecret = localStorage.getItem('wallet_secret');
    if (savedSecret) secretInput.value = savedSecret;

    function setStatus(message, isError) {
      statusMsg.textContent = message;
      statusMsg.className = 'status-msg ' + (isError ? 'error' : 'success');
      log(message, isError ? 'error' : 'success');
    }

    async function loadWallets() {
      const secret = secretInput.value.trim();
      if (!secret) {
        setStatus('Service secret required.', true);
        return;
      }
      localStorage.setItem('wallet_secret', secret);
      setStatus('Loading wallets...', false);

      try {
        const response = await fetch('/wallets', {
          headers: { Authorization: 'Bearer ' + secret },
        });
        const text = await response.text();
        if (!response.ok) {
          setStatus('Failed: ' + (text || response.statusText), true);
          walletsContainer.innerHTML = '';
          return;
        }
        const data = text ? JSON.parse(text) : { wallets: [] };
        renderWallets(data.wallets || []);
        setStatus('Loaded ' + (data.wallets?.length || 0) + ' wallets', false);
      } catch (err) {
        setStatus('Network error loading wallets.', true);
      }
    }

    function renderWallets(wallets) {
      walletsContainer.innerHTML = '';
      if (!wallets.length) {
        const p = document.createElement('p');
        p.style.cssText = 'font-size:0.8rem; color:var(--text-muted); text-align:center; padding:2rem 0;';
        p.textContent = 'No wallets found.';
        walletsContainer.appendChild(p);
        return;
      }
      wallets.forEach(wallet => {
        const card = document.createElement('div');
        card.className = 'wallet-card';
        const purpose = document.createElement('div');
        purpose.className = 'wallet-purpose';
        purpose.textContent = wallet.purpose;
        const address = document.createElement('div');
        address.className = 'wallet-address';
        address.textContent = wallet.publicKey;
        const input = document.createElement('input');
        input.type = 'text';
        input.className = 'sleek-input';
        input.dataset.purpose = wallet.purpose;
        input.value = wallet.label || '';
        input.placeholder = 'Wallet label (optional)';
        input.style.marginBottom = '0';
        card.appendChild(purpose);
        card.appendChild(address);
        card.appendChild(input);
        walletsContainer.appendChild(card);
      });
    }

    async function saveLabels() {
      const secret = secretInput.value.trim();
      if (!secret) {
        setStatus('Service secret required.', true);
        return;
      }

      const inputs = walletsContainer.querySelectorAll('input[data-purpose]');
      if (!inputs.length) {
        setStatus('No wallets loaded.', true);
        return;
      }

      for (const input of inputs) {
        const purpose = input.getAttribute('data-purpose');
        const label = input.value;
        try {
          const response = await fetch('/wallets/labels', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              Authorization: 'Bearer ' + secret,
            },
            body: JSON.stringify({ purpose, label }),
          });
          if (!response.ok) {
            const text = await response.text();
            setStatus('Failed to save: ' + text, true);
            return;
          }
        } catch (err) {
          setStatus('Network error saving labels.', true);
          return;
        }
      }
      setStatus('Labels saved successfully.', false);
    }
  </script>
</body>
</html>`;
}

app.get('/dashboard', (_req, res) => {
  res.setHeader('Content-Type', 'text/html');
  res.send(getDashboardHtml());
});

/**
 * Validate that a transaction only contains allowed instructions.
 * Returns null if valid, or an error message if invalid.
 */
async function validateTransactionInstructions(
  transaction: Transaction,
  vaultPublicKey: PublicKey
): Promise<string | null> {
  const instructions = transaction.instructions;

  if (instructions.length === 0) {
    return 'Transaction has no instructions';
  }

  // Maximum 3 instructions (ATA creation + transfer + optional memo)
  if (instructions.length > 3) {
    return `Too many instructions: ${instructions.length} (max 3)`;
  }

  for (let i = 0; i < instructions.length; i++) {
    const ix = instructions[i];
    const programId = ix.programId;

    // Allow: Token Program (for transfers)
    if (programId.equals(TOKEN_PROGRAM_ID)) {
      // Decode instruction type - first byte indicates instruction type
      const instructionType = ix.data[0];

      // Token Program instruction types:
      // 3 = Transfer, 12 = TransferChecked
      if (instructionType !== 3 && instructionType !== 12) {
        return `Invalid Token instruction type: ${instructionType}. Only Transfer (3) or TransferChecked (12) allowed`;
      }

      // For Transfer instruction, validate source account
      // Keys: [0]=source, [1]=destination, [2]=authority
      if (ix.keys.length < 3) {
        return 'Invalid Transfer instruction: insufficient accounts';
      }

      const authority = ix.keys[2].pubkey;
      if (!authority.equals(vaultPublicKey)) {
        return `Invalid authority: ${authority.toBase58()}. Expected vault: ${vaultPublicKey.toBase58()}`;
      }

      continue;
    }

    // Allow: Associated Token Program (for ATA creation)
    if (programId.equals(ASSOCIATED_TOKEN_PROGRAM_ID)) {
      // ATA creation is allowed - vault may need to create recipient ATA
      // Keys: [0]=payer, [1]=ata, [2]=owner, [3]=mint, [4]=system, [5]=token
      if (ix.keys.length < 4) {
        return 'Invalid ATA instruction: insufficient accounts';
      }

      // Verify payer is the vault
      const payer = ix.keys[0].pubkey;
      if (!payer.equals(vaultPublicKey)) {
        return `Invalid ATA payer: ${payer.toBase58()}. Expected vault: ${vaultPublicKey.toBase58()}`;
      }

      continue;
    }

    // Allow: System Program (for rent-exempt ATA creation)
    const SYSTEM_PROGRAM_ID = new PublicKey('11111111111111111111111111111111');
    if (programId.equals(SYSTEM_PROGRAM_ID)) {
      // System program calls are typically part of ATA creation
      continue;
    }

    // Allow: Compute Budget Program (for priority fees)
    const COMPUTE_BUDGET_ID = new PublicKey('ComputeBudget111111111111111111111111111111');
    if (programId.equals(COMPUTE_BUDGET_ID)) {
      continue;
    }

    // Reject any other program
    return `Unauthorized program: ${programId.toBase58()}`;
  }

  return null; // Valid
}

/**
 * Sign a transaction constructed by the Marketplace API.
 *
 * Body: { transactionBase64: string }
 */
app.post('/sign-transaction', authMiddleware, async (req, res) => {
  try {
    const { transactionBase64 } = req.body;
    const purpose = (req.query?.purpose as string) || 'vault';

    if (!VALID_PURPOSES.has(purpose)) {
      return res.status(400).json({ error: 'Invalid purpose' });
    }
    if (!transactionBase64) {
      return res.status(400).json({ error: 'Missing transactionBase64' });
    }

    // 1. Recover Transaction
    const txBuffer = Buffer.from(transactionBase64, 'base64');
    const transaction = Transaction.from(txBuffer);

    // 2. Get Secure Key
    const keypair = await getVaultKey(purpose);

    // 3. Security Check: Validate transaction instructions
    const validationError = await validateTransactionInstructions(transaction, keypair.publicKey);
    if (validationError) {
      console.error(`[TEE] Transaction validation failed: ${validationError}`);
      return res.status(400).json({
        error: 'Transaction validation failed',
        reason: validationError,
      });
    }

    // 4. Partial Sign
    transaction.partialSign(keypair);

    // 5. Serialize and return
    // requireAllSignatures=false because we might just be one signer (e.g. payer might be elsewhere, though usually vault pays or API pays)
    const signedTxBase64 = transaction
      .serialize({ requireAllSignatures: false })
      .toString('base64');

    console.log(`[TEE] Signed ${purpose} transaction for ${keypair.publicKey.toBase58()}`);

    res.json({
      success: true,
      signedTransaction: signedTxBase64,
    });
  } catch (error: any) {
    console.error('Signing error:', error);
    res.status(500).json({ error: error.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`[TEE] Verifiable Wallet Service running on port ${PORT}`);
});
