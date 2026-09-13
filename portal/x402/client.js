// Browser-only Sui wallet helper for Portal x402 routes.
// Native clients should call /x402/prepare, sign the returned transaction with
// their own Sui runtime, then send the resulting payload as X-PAYMENT.
import { getWallets } from 'https://esm.sh/@wallet-standard/app@1.1.1';
import { Transaction } from 'https://esm.sh/@mysten/sui@2.17.0/transactions';

const walletAPI = getWallets();

export function getSuiWallets({ network = '' } = {}) {
    network = String(network || '').trim();
    return walletAPI.get().map((wallet, index) => {
        const features = wallet.features || {};
        const connect = features['standard:connect']?.connect?.bind(features['standard:connect']);
        const sign = features['sui:signTransaction']?.signTransaction?.bind(features['sui:signTransaction']);
        const signBlock = features['sui:signTransactionBlock']?.signTransactionBlock?.bind(features['sui:signTransactionBlock']);
        if (!connect || (!sign && !signBlock)) {
            return null;
        }

        const out = {
            id: wallet.name || `wallet-${index}`,
            name: wallet.name || `Wallet ${index + 1}`,
            async accounts(chain = network) {
                const connected = await connect();
                return normalizeAccounts(connected?.accounts || wallet.accounts || [])
                    .filter((account) => !chain || !Array.isArray(account.chains) || account.chains.includes(chain));
            },
            async connect(chain = network, address = '') {
                const accounts = await out.accounts(chain);
                const normalizedAddress = String(address || '').trim().toLowerCase();
                if (normalizedAddress) {
                    const account = accounts.find((candidate) => String(candidate.address || '').trim().toLowerCase() === normalizedAddress);
                    if (!account) {
                        throw new Error('Selected account is not available in the connected wallet');
                    }
                    return account;
                }
                if (accounts.length !== 1) {
                    if (accounts.length > 1) {
                        throw new Error('Select a Sui account before paying');
                    }
                    throw new Error('Connected wallet did not return an account');
                }
                return accounts[0];
            },
            async signTransaction(account, transaction, chain = network) {
                if (sign) {
                    return sign({ account, chain, transaction });
                }
                return signBlock({ account, chain, transactionBlock: transaction });
            },
        };

        const execute = features['sui:signAndExecuteTransaction']?.signAndExecuteTransaction?.bind(features['sui:signAndExecuteTransaction']);
        const executeBlock = features['sui:signAndExecuteTransactionBlock']?.signAndExecuteTransactionBlock?.bind(features['sui:signAndExecuteTransactionBlock']);
        if (execute || executeBlock) {
            out.executeTransaction = async (account, transaction, chain = network) => {
                if (execute) {
                    return execute({ account, chain, transaction, options: { showEffects: true } });
                }
                return executeBlock({ account, chain, transactionBlock: transaction, options: { showEffects: true } });
            };
        }
        return out;
    }).filter(Boolean);
}

export function onSuiWalletChange(callback) {
    if (typeof walletAPI.on !== 'function') {
        return () => {};
    }
    const offRegister = walletAPI.on('register', callback);
    const offUnregister = walletAPI.on('unregister', callback);
    return () => {
        offRegister?.();
        offUnregister?.();
    };
}

export async function prepareX402Payment(options = {}) {
    const fetcher = options.fetch || fetch.bind(globalThis);
    const signal = options.signal;
    const method = String(options.method || 'GET').trim().toUpperCase();
    const path = String(options.path || '').trim();
    if (!path || !path.startsWith('/')) {
        throw new Error(path ? 'path must start with /' : 'path is required');
    }

    const wallet = options.wallet || getSuiWallets({ network: options.network })[0];
    if (!wallet) {
        throw new Error('No Sui wallet selected');
    }

    emitPaymentEvent(options, 'wallet.connect', 'Connecting wallet');
    const network = String(options.network || '').trim();
    const account = options.account || await wallet.connect(network, options.address);
    if (!account?.address) {
        throw new Error('Connected wallet did not return an account');
    }
    if (network && Array.isArray(account.chains) && !account.chains.includes(network)) {
        throw new Error(`Connected account does not advertise ${network}`);
    }

    emitPaymentEvent(options, 'payment.prepare', 'Preparing USDC transaction', { method, path });
    const prepareURL = options.preparePath || '/x402/prepare';
    const prepareBody = { sender: account.address, method, path };
    let prepared = await requestPrepare(fetcher, prepareURL, prepareBody, signal);
    let paymentNetwork = String(prepared.paymentRequirements?.network || network).trim();
    if (paymentNetwork && Array.isArray(account.chains) && !account.chains.includes(paymentNetwork)) {
        throw new Error(`Connected account does not advertise ${paymentNetwork}`);
    }

    if (prepared.prepareTransaction?.transaction) {
        if (!wallet.executeTransaction) {
            throw new Error('Selected wallet cannot execute the USDC prepare transaction');
        }
        emitPaymentEvent(options, 'balance.prepare', 'Preparing object balance in wallet', { network: paymentNetwork });
        const prepareResult = await wallet.executeTransaction(account, Transaction.from(fromBase64(prepared.prepareTransaction.transaction)), paymentNetwork);
        const prepareStatus = prepareResult?.effects?.status?.status || prepareResult?.effects?.status;
        if (prepareStatus && prepareStatus !== 'success') {
            throw new Error(prepareResult.effects?.status?.error || 'USDC prepare transaction failed');
        }

        const pollAttempts = nonNegativeIntegerOption(options.preparePollAttempts, 20);
        const pollIntervalMs = positiveIntegerOption(options.preparePollIntervalMs, 1000);
        emitPaymentEvent(options, 'balance.wait', 'Waiting for prepared balance', {
            attempts: pollAttempts,
            intervalMs: pollIntervalMs,
        });
        for (let attempt = 0; attempt < pollAttempts && prepared.prepareTransaction?.transaction; attempt += 1) {
            await delay(pollIntervalMs, signal);
            prepared = await requestPrepare(fetcher, prepareURL, prepareBody, signal);
            paymentNetwork = String(prepared.paymentRequirements?.network || paymentNetwork).trim();
            emitPaymentEvent(options, 'balance.poll', 'Checking prepared balance', {
                attempt: attempt + 1,
                attempts: pollAttempts,
            });
        }
        if (prepared.prepareTransaction?.transaction) {
            throw new Error('Prepared USDC balance is not indexed yet');
        }
    }

    if (!prepared.paymentTransaction?.transaction) {
        throw new Error('Payment prepare response is missing a payment transaction');
    }
    emitPaymentEvent(options, 'payment.sign', 'Signing x402 payment', { network: paymentNetwork });
    const signed = await wallet.signTransaction(account, Transaction.from(fromBase64(prepared.paymentTransaction.transaction)), paymentNetwork);
    const signature = typeof signed?.signature === 'string' ? signed.signature : (Array.isArray(signed?.signatures) ? signed.signatures[0] : '');
    const transaction = signed?.bytes || signed?.transactionBlockBytes || prepared.paymentTransaction.transaction;
    const transactionBytes = transaction instanceof Uint8Array ? toBase64(transaction) : transaction;
    if (!signature || !transactionBytes) {
        throw new Error('Wallet did not return a signed payment transaction');
    }
    if (transactionBytes !== prepared.paymentTransaction.transaction) {
        throw new Error('Wallet returned different payment transaction bytes');
    }

    const payload = {
        x402Version: prepared.x402Version,
        payload: {
            signature,
            transaction: transactionBytes,
        },
        accepted: prepared.paymentRequirements,
        resource: prepared.resource,
    };
    return {
        account,
        prepared,
        payload,
        paymentHeader: toBase64(new TextEncoder().encode(JSON.stringify(payload))),
    };
}

export async function x402Fetch(input, init = {}, options = {}) {
    const request = input instanceof Request ? new Request(input, init) : new Request(new URL(String(input), globalThis.location.href).href, init);
    const signal = options.signal || request.signal;
    const paid = await prepareX402Payment({
        ...options,
        signal,
        method: request.method,
        path: options.path || new URL(request.url).pathname,
    });

    emitPaymentEvent(options, 'payment.settle', 'Settling payment');
    const headers = new Headers(request.headers);
    headers.set('X-PAYMENT', paid.paymentHeader);
    return (options.fetch || fetch.bind(globalThis))(new Request(request, { headers, signal }));
}

async function requestPrepare(fetcher, prepareURL, prepareBody, signal) {
    const response = await fetcher(prepareURL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        signal,
        body: JSON.stringify(prepareBody),
    });
    if (!response.ok) {
        throw new Error(await response.text());
    }
    return response.json();
}

function emitPaymentEvent(options, type, message, data = {}) {
    options.onEvent?.({ type, message, data });
    options.onStatus?.(message);
}

function nonNegativeIntegerOption(value, fallback) {
    const number = Number(value);
    if (!Number.isFinite(number) || number < 0) {
        return fallback;
    }
    return Math.floor(number);
}

function positiveIntegerOption(value, fallback) {
    const number = Number(value);
    if (!Number.isFinite(number) || number <= 0) {
        return fallback;
    }
    return Math.floor(number);
}

function delay(ms, signal) {
    if (signal?.aborted) {
        return Promise.reject(abortError());
    }
    return new Promise((resolve, reject) => {
        const timeout = setTimeout(resolve, ms);
        signal?.addEventListener('abort', () => {
            clearTimeout(timeout);
            reject(abortError());
        }, { once: true });
    });
}

function abortError() {
    if (typeof DOMException === 'function') {
        return new DOMException('Aborted', 'AbortError');
    }
    const error = new Error('Aborted');
    error.name = 'AbortError';
    return error;
}

function normalizeAccounts(value) {
    const accounts = Array.isArray(value) ? value : (value ? [value] : []);
    return accounts.map((account) => {
        if (typeof account === 'string') {
            return { address: account };
        }
        return account && typeof account.address === 'string' ? account : null;
    }).filter(Boolean);
}

function fromBase64(value) {
    return Uint8Array.from(atob(value), (char) => char.charCodeAt(0));
}

function toBase64(bytes) {
    let binary = '';
    for (let i = 0; i < bytes.length; i += 0x8000) {
        binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
    }
    return btoa(binary);
}
