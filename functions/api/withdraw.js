const MIN_WITHDRAWAL = 0.0000001;


/* =====================================================
   BITCOIN ADDRESS VALIDATION
   =====================================================

   Supports:

   - Legacy P2PKH: 1...
   - P2SH:          3...
   - Native SegWit: bc1q...
   - Taproot:       bc1p...

   Performs:

   - Base58Check validation
   - Bech32 checksum validation
   - Bech32m checksum validation
   - Witness version validation
   - Witness program length validation
*/


const BASE58_ALPHABET =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";


const BECH32_CHARSET =
    "qpzry9x8gf2tvdw0s3jn54khce6mua7l";


const BECH32_CONST =
    1;


const BECH32M_CONST =
    0x2bc830a3;


/* =====================================================
   SHA-256
   ===================================================== */

async function sha256(bytes) {

    return new Uint8Array(
        await crypto.subtle.digest(
            "SHA-256",
            bytes
        )
    );
}


/* =====================================================
   BASE58 DECODE
   ===================================================== */

function base58Decode(address) {

    let num = 0n;

    for (const char of address) {

        const index =
            BASE58_ALPHABET.indexOf(char);

        if (index === -1) {
            return null;
        }

        num =
            num * 58n +
            BigInt(index);
    }


    let hex =
        num.toString(16);


    if (hex.length % 2 !== 0) {
        hex = "0" + hex;
    }


    const bytes = [];


    for (
        let i = 0;
        i < hex.length;
        i += 2
    ) {

        bytes.push(
            parseInt(
                hex.slice(i, i + 2),
                16
            )
        );
    }


    /*
     * Preserve leading zero bytes.
     *
     * In Base58 Bitcoin addresses,
     * leading "1" characters represent
     * zero bytes.
     */

    let leadingZeros = 0;


    for (
        const char of address
    ) {

        if (char !== "1") {
            break;
        }

        leadingZeros++;
    }


    return new Uint8Array([
        ...new Array(
            leadingZeros
        ).fill(0),

        ...bytes
    ]);
}


/* =====================================================
   BASE58CHECK VALIDATION
   ===================================================== */

async function isValidBase58Check(address) {

    const decoded =
        base58Decode(address);


    if (!decoded) {
        return false;
    }


    /*
     * Bitcoin Base58Check address:

     * 1 byte  version
     * 20 bytes payload
     * 4 bytes checksum
     *
     * Total = 25 bytes
     */

    if (decoded.length !== 25) {
        return false;
    }


    const version =
        decoded[0];


    /*
     * Bitcoin mainnet:

     * 0x00 = P2PKH → 1...
     * 0x05 = P2SH  → 3...
     */

    if (
        version !== 0x00 &&
        version !== 0x05
    ) {
        return false;
    }


    const payload =
        decoded.slice(
            0,
            21
        );


    const checksum =
        decoded.slice(
            21
        );


    /*
     * Base58Check checksum:

     * SHA256(SHA256(version + payload))
     * first 4 bytes
     */

    const hash1 =
        await sha256(payload);


    const hash2 =
        await sha256(hash1);


    const expectedChecksum =
        hash2.slice(
            0,
            4
        );


    for (
        let i = 0;
        i < 4;
        i++
    ) {

        if (
            checksum[i] !==
            expectedChecksum[i]
        ) {
            return false;
        }
    }


    return true;
}


/* =====================================================
   BECH32 POLYMOD
   ===================================================== */

function bech32Polymod(values) {

    const generator = [
        0x3b6a57b2,
        0x26508e6d,
        0x1ea119fa,
        0x3d4233dd,
        0x2a1462b3
    ];


    let chk = 1;


    for (
        const value of values
    ) {

        const top =
            chk >>> 25;


        chk =
            (
                (chk & 0x1ffffff) << 5
            ) ^
            value;


        for (
            let i = 0;
            i < 5;
            i++
        ) {

            if (
                (top >>> i) & 1
            ) {

                chk ^=
                    generator[i];
            }
        }
    }


    return chk >>> 0;
}


/* =====================================================
   BECH32 HRP EXPAND
   ===================================================== */

function bech32HrpExpand(hrp) {

    const high = [];
    const low = [];


    for (
        const char of hrp
    ) {

        const code =
            char.charCodeAt(0);


        high.push(
            code >> 5
        );


        low.push(
            code & 31
        );
    }


    return [
        ...high,
        0,
        ...low
    ];
}


/* =====================================================
   CONVERT BITS
   ===================================================== */

function convertBits(
    data,
    fromBits,
    toBits,
    pad
) {

    let acc = 0;
    let bits = 0;

    const ret = [];


    const maxv =
        (1 << toBits) - 1;


    const maxAcc =
        (1 << (fromBits + toBits - 1)) - 1;


    for (
        const value of data
    ) {

        if (
            value < 0 ||
            (value >> fromBits) !== 0
        ) {
            return null;
        }


        acc =
            (
                (acc << fromBits) |
                value
            ) &
            maxAcc;


        bits += fromBits;


        while (
            bits >= toBits
        ) {

            bits -= toBits;


            ret.push(
                (
                    acc >> bits
                ) &
                maxv
            );
        }
    }


    if (pad) {

        if (bits > 0) {

            ret.push(
                (
                    acc <<
                    (toBits - bits)
                ) &
                maxv
            );
        }

    } else {

        /*
         * Invalid if there are
         * too many leftover bits.
         */

        if (
            bits >= fromBits
        ) {
            return null;
        }


        /*
         * Remaining bits must be zero.
         */

        if (
            (
                acc <<
                (toBits - bits)
            ) &
            maxv
        ) {
            return null;
        }
    }


    return ret;
}


/* =====================================================
   BECH32 / BECH32M VALIDATION
   ===================================================== */

function decodeBech32(address) {

    /*
     * Bech32 cannot use mixed case.
     *
     * All lowercase OR all uppercase
     * is allowed.
     */

    const lower =
        address.toLowerCase();


    const upper =
        address.toUpperCase();


    if (
        address !== lower &&
        address !== upper
    ) {
        return null;
    }


    const normalized =
        lower;


    /*
     * Bitcoin mainnet only.
     */

    if (
        !normalized.startsWith("bc1")
    ) {
        return null;
    }


    /*
     * BIP-173 maximum length.
     */

    if (
        normalized.length < 14 ||
        normalized.length > 90
    ) {
        return null;
    }


    /*
     * Separator is the final "1".
     */

    const separator =
        normalized.lastIndexOf("1");


    if (
        separator < 1 ||
        separator + 7 >
        normalized.length
    ) {
        return null;
    }


    const hrp =
        normalized.slice(
            0,
            separator
        );


    const dataPart =
        normalized.slice(
            separator + 1
        );


    const data = [];


    for (
        const char of dataPart
    ) {

        const value =
            BECH32_CHARSET.indexOf(
                char
            );


        if (value === -1) {
            return null;
        }


        data.push(value);
    }


    /*
     * Need at least:

     * 1 witness version
     * 6 checksum values
     */

    if (
        data.length < 7
    ) {
        return null;
    }


    const polymod =
        bech32Polymod([
            ...bech32HrpExpand(hrp),
            ...data
        ]);


    let encoding;


    if (
        polymod === BECH32_CONST
    ) {

        encoding =
            "bech32";

    } else if (
        polymod === BECH32M_CONST
    ) {

        encoding =
            "bech32m";

    } else {

        /*
         * Invalid checksum.
         */

        return null;
    }


    /*
     * First data value is
     * the witness version.
     */

    const witnessVersion =
        data[0];


    if (
        witnessVersion > 16
    ) {
        return null;
    }


    /*
     * Remove:

     * witness version
     * 6 checksum values
     */

    const program =
        convertBits(
            data.slice(1, -6),
            5,
            8,
            false
        );


    if (!program) {
        return null;
    }


    /*
     * Witness program:

     * minimum 2 bytes
     * maximum 40 bytes
     */

    if (
        program.length < 2 ||
        program.length > 40
    ) {
        return null;
    }


    /*
     * Witness version 0:

     * P2WPKH = 20 bytes
     * P2WSH  = 32 bytes
     */

    if (
        witnessVersion === 0 &&
        program.length !== 20 &&
        program.length !== 32
    ) {
        return null;
    }


    /*
     * Witness version 0 MUST use Bech32.
     */

    if (
        witnessVersion === 0 &&
        encoding !== "bech32"
    ) {
        return null;
    }


    /*
     * Witness version 1+
     * MUST use Bech32m.
     */

    if (
        witnessVersion !== 0 &&
        encoding !== "bech32m"
    ) {
        return null;
    }


    return true;
}


/* =====================================================
   FINAL BITCOIN ADDRESS VALIDATION
   ===================================================== */

async function isValidBitcoinAddress(address) {

    if (
        typeof address !== "string"
    ) {
        return false;
    }


    const value =
        address.trim();


    if (!value) {
        return false;
    }


    /*
     * Legacy / P2SH
     */

    if (
        value.startsWith("1") ||
        value.startsWith("3")
    ) {

        return await isValidBase58Check(
            value
        );
    }


    /*
     * Native SegWit / Taproot
     */

    if (
        value.toLowerCase().startsWith("bc1")
    ) {

        return (
            decodeBech32(value) === true
        );
    }


    return false;
}


/* =====================================================
   GET COOKIE VALUE
   ===================================================== */

function getCookie(request, name) {

    const cookieHeader =
        request.headers.get("Cookie");


    if (!cookieHeader) {
        return null;
    }


    for (
        const cookie of
        cookieHeader.split(";")
    ) {

        const [key, ...value] =
            cookie.trim().split("=");


        if (key === name) {

            return value.join("=");
        }
    }


    return null;
}


/* =====================================================
   SHA-256 SESSION TOKEN HASH
   ===================================================== */

async function hashSessionToken(token) {

    const data =
        new TextEncoder().encode(token);


    const hash =
        await crypto.subtle.digest(
            "SHA-256",
            data
        );


    return Array.from(
        new Uint8Array(hash)
    )
        .map(
            byte =>
                byte
                    .toString(16)
                    .padStart(2, "0")
        )
        .join("");
}


/* =====================================================
   STANDARD JSON RESPONSE
   ===================================================== */

function jsonResponse(
    data,
    status = 200
) {

    return Response.json(
        data,
        {
            status,

            headers: {
                "Cache-Control":
                    "no-store, no-cache, must-revalidate, max-age=0",

                "Pragma":
                    "no-cache",

                "Expires":
                    "0"
            }
        }
    );
}


/* =====================================================
   WITHDRAWAL API
   ===================================================== */

export async function onRequestPost(context) {

    try {

        /*
         * D1 SESSION
         */

        const db =
            context.env.DB.withSession(
                "first-primary"
            );


        /* =================================================
           1. READ REQUEST
           ================================================= */

        let data;


        try {

            data =
                await context.request.json();

        } catch {

            return jsonResponse(
                {
                    success: false,
                    error:
                        "Invalid request."
                },
                400
            );
        }


        const amount =
            Number(data.amount);


        const walletAddress =
            String(
                data.walletAddress || ""
            ).trim();


        /*
         * BTC ONLY
         */

        const currency =
            "BTC";


        /* =================================================
           2. AMOUNT VALIDATION
           ================================================= */

        if (
            !Number.isFinite(amount) ||
            amount <= 0
        ) {

            return jsonResponse(
                {
                    success: false,
                    error:
                        "Invalid withdrawal amount."
                },
                400
            );
        }


        if (
            amount < MIN_WITHDRAWAL
        ) {

            return jsonResponse(
                {
                    success: false,
                    error:
                        "Minimum withdrawal is 0.0000001 BTC."
                },
                400
            );
        }


        /*
         * BTC has 8 decimal places.
         *
         * Convert to satoshis first.
         */

        const satoshis =
            Math.round(
                amount * 100000000
            );


        if (
            !Number.isSafeInteger(
                satoshis
            ) ||
            satoshis <= 0
        ) {

            return jsonResponse(
                {
                    success: false,
                    error:
                        "Invalid BTC amount."
                },
                400
            );
        }


        const normalizedAmount =
            satoshis / 100000000;


        if (
            normalizedAmount !== amount
        ) {

            return jsonResponse(
                {
                    success: false,
                    error:
                        "BTC amount can have a maximum of 8 decimal places."
                },
                400
            );
        }


        /* =================================================
           3. WALLET VALIDATION
           ================================================= */

        if (!walletAddress) {

            return jsonResponse(
                {
                    success: false,
                    error:
                        "Bitcoin wallet address is required."
                },
                400
            );
        }


        if (
            !(await isValidBitcoinAddress(
                walletAddress
            ))
        ) {

            return jsonResponse(
                {
                    success: false,
                    error:
                        "Invalid Bitcoin wallet address."
                },
                400
            );
        }


        /* =================================================
           4. SESSION
           ================================================= */

        const sessionToken =
            getCookie(
                context.request,
                "session"
            );


        if (!sessionToken) {

            return jsonResponse(
                {
                    success: false,
                    error:
                        "Please login first."
                },
                401
            );
        }


        const tokenHash =
            await hashSessionToken(
                sessionToken
            );


        /* =================================================
           5. VERIFY SESSION
           ================================================= */

        const session =
            await db
                .prepare(
                    `SELECT
                        user_id,
                        expires_at
                     FROM sessions
                     WHERE token_hash = ?
                       AND expires_at > CURRENT_TIMESTAMP
                     LIMIT 1`
                )
                .bind(tokenHash)
                .first();


        if (!session) {

            return jsonResponse(
                {
                    success: false,
                    error:
                        "Invalid or expired session."
                },
                401
            );
        }


        const userId =
            Number(session.user_id);


        if (
            !Number.isInteger(userId) ||
            userId <= 0
        ) {

            return jsonResponse(
                {
                    success: false,
                    error:
                        "Invalid user session."
                },
                401
            );
        }


        /* =================================================
           6. VERIFY USER
           ================================================= */

        const user =
            await db
                .prepare(
                    `SELECT
                        id,
                        balance
                     FROM users
                     WHERE id = ?
                     LIMIT 1`
                )
                .bind(userId)
                .first();


        if (!user) {

            return jsonResponse(
                {
                    success: false,
                    error:
                        "User account not found."
                },
                404
            );
        }


        /* =================================================
           7. FRIENDLY DUPLICATE CHECK
           ================================================= */

        const existingWithdrawal =
            await db
                .prepare(
                    `SELECT
                        id,
                        status
                     FROM withdrawals
                     WHERE user_id = ?
                       AND status IN
                           ('pending', 'processing')
                     LIMIT 1`
                )
                .bind(userId)
                .first();


        if (existingWithdrawal) {

            return jsonResponse(
                {
                    success: false,
                    error:
                        "You already have a withdrawal being processed."
                },
                409
            );
        }


        /* =================================================
           8. CREATE WITHDRAWAL
           ================================================= */

        let withdrawalResult
