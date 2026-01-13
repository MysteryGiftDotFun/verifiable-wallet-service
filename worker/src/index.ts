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
const SERVICE_SECRET = process.env.WALLET_SERVICE_SECRET || 'dev-secret';

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
const LABELS_PATH =
  process.env.WALLET_LABELS_PATH || path.join(process.cwd(), 'data', 'wallet-labels.json');
const MAX_LABEL_LENGTH = 120;
const TOKEN_METADATA_PROGRAM_ID = new PublicKey('metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s');
const MAX_METADATA_NAME = 32;
const MAX_METADATA_SYMBOL = 10;

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
    version: process.env.APP_VERSION || 'dev',
    tee: process.env.PHALA_TEE ? 'active' : 'simulated',
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

const DASHBOARD_HTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Verifiable Wallet Dashboard</title>
  <style>
    :root {
      --bg: #0c0c10;
      --card: #15151c;
      --border: #272737;
      --text: #e8ecf3;
      --muted: #8a90a2;
      --accent: #7dd3fc;
      --accent-2: #a78bfa;
      --error: #ff6b6b;
      --success: #6bd975;
      --mono: ui-monospace, SFMono-Regular, Menlo, monospace;
    }
    * { box-sizing: border-box; }
    body { font-family: 'Inter', system-ui, -apple-system, sans-serif; background: radial-gradient(circle at 20% 20%, rgba(125,211,252,0.08), transparent 30%), radial-gradient(circle at 80% 0%, rgba(167,139,250,0.08), transparent 25%), var(--bg); color: var(--text); margin: 0; padding: 24px; }
    h1 { margin: 0 0 16px; font-size: 22px; letter-spacing: 0.5px; }
    .card { background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 16px; margin-bottom: 16px; box-shadow: 0 10px 40px rgba(0,0,0,0.25); }
    .row { display: flex; flex-wrap: wrap; gap: 12px; }
    label { font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.6px; }
    input { width: 100%; background: #0f0f15; border: 1px solid var(--border); color: var(--text); padding: 10px 12px; border-radius: 10px; font-size: 14px; }
    input:focus { outline: 1px solid var(--accent); box-shadow: 0 0 0 3px rgba(125,211,252,0.15); }
    button { background: linear-gradient(135deg, var(--accent), var(--accent-2)); color: #0b0b0f; border: none; padding: 10px 14px; border-radius: 10px; cursor: pointer; font-weight: 600; letter-spacing: 0.3px; }
    button.secondary { background: #1c1c24; color: var(--text); border: 1px solid var(--border); }
    .wallet { border-top: 1px solid var(--border); padding-top: 12px; margin-top: 12px; }
    .mono { font-family: var(--mono); font-size: 12px; color: var(--accent); }
    .status { font-size: 12px; color: var(--success); }
    .error { font-size: 12px; color: var(--error); }
    .stack { display: grid; gap: 12px; }
  </style>
</head>
<body>
  <h1>Verifiable Wallet Service</h1>
  <div class="card">
    <div class="row">
      <div style="flex: 1; min-width: 220px;">
        <label>Service Secret</label>
        <input id="secret" placeholder="Bearer token" type="password" />
      </div>
      <div style="flex: 1; min-width: 220px; display: grid; align-content: center; gap: 6px;">
        <label>Status</label>
        <div id="status" class="status">Enter secret to load wallets.</div>
        <div id="error" class="error"></div>
      </div>
    </div>
    <div style="margin-top: 12px; display: flex; gap: 10px;">
      <button id="load" type="button">Load Wallets</button>
      <button id="save" type="button" class="secondary">Save Labels</button>
    </div>
  </div>
  <div id="wallets"></div>

  <script>
    const statusEl = document.getElementById('status');
    const errorEl = document.getElementById('error');
    const walletsEl = document.getElementById('wallets');
    const secretInput = document.getElementById('secret');
    const savedSecret = localStorage.getItem('wallet_secret');
    if (savedSecret) secretInput.value = savedSecret;

    function setStatus(message, isError) {
      statusEl.textContent = message;
      errorEl.textContent = isError ? message : '';
      statusEl.className = isError ? 'error' : 'status';
    }

    async function fetchWallets() {
      const secret = secretInput.value.trim();
      if (!secret) {
        setStatus('Service secret required.', true);
        return;
      }
      localStorage.setItem('wallet_secret', secret);
      setStatus('Loading wallets...');

      try {
        const response = await fetch('/wallets', {
          headers: { Authorization: 'Bearer ' + secret },
        });
        const text = await response.text();
        if (!response.ok) {
          setStatus('Failed to load wallets: ' + text, true);
          walletsEl.innerHTML = '';
          return;
        }
        const data = text ? JSON.parse(text) : { wallets: [] };
        renderWallets(data.wallets || []);
        setStatus('Loaded wallets.');
      } catch (err) {
        setStatus('Network error loading wallets.', true);
      }
    }

    function renderWallets(wallets) {
      walletsEl.innerHTML = '';
      if (!wallets.length) {
        walletsEl.innerHTML = '<div class="card">No wallets returned.</div>';
        return;
      }
      wallets.forEach((wallet) => {
        const wrapper = document.createElement('div');
        wrapper.className = 'card wallet stack';
        wrapper.innerHTML = [
          '<div><strong>Purpose:</strong> ' + wallet.purpose + '</div>',
          '<div class="mono">' + wallet.publicKey + '</div>',
          '<div class="stack">',
          '<label>Label</label>',
          '<input data-purpose="' + wallet.purpose + '" value="' + (wallet.label || '') + '" />',
          '</div>',
        ].join('');
        walletsEl.appendChild(wrapper);
      });
    }

    async function saveLabels() {
      const secret = secretInput.value.trim();
      if (!secret) {
        setStatus('Service secret required.', true);
        return;
      }

      const inputs = walletsEl.querySelectorAll('input[data-purpose]');
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
            setStatus('Failed to save labels: ' + text, true);
            return;
          }
        } catch (err) {
          setStatus('Network error saving labels.', true);
          return;
        }
      }
      setStatus('Labels saved.');
    }

    document.getElementById('load').addEventListener('click', fetchWallets);
    document.getElementById('save').addEventListener('click', saveLabels);
  </script>
</body>
</html>`;

app.get('/dashboard', (_req, res) => {
  res.setHeader('Content-Type', 'text/html');
  res.send(DASHBOARD_HTML);
});

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

    // 3. Security Check (Optional but recommended)
    // Ensure we are only signing specific types of txs?
    // For now, we trust the Marketplace API via SERVICE_SECRET.
    // Future: Inspect instructions to ensure it's a valid NFT transfer.

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
