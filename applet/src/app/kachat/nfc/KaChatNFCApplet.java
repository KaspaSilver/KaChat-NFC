package app.kachat.nfc;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;
import javacard.framework.Util;
import javacard.security.MessageDigest;

/**
 * Stores one encrypted backup behind a PIN.
 *
 * This applet never generates, derives or uses a wallet key. It has no random number generator
 * and no key objects, and CI fails the build if either is ever imported. It holds bytes the app
 * has already encrypted and hands them back after the right PIN. See docs/PROTOCOL.md.
 *
 * A save is written beside the current backup and only replaces it on a commit whose SHA-256
 * matches, so pulling the card away mid-save leaves the old backup intact.
 *
 * The PIN is set once and can't be changed. A forgotten PIN means reinstalling the applet with the
 * card's admin key, which erases the backup and the PIN.
 */
public final class KaChatNFCApplet extends Applet {
    private static final byte CLA = (byte) 0x80;

    private static final byte INS_STATUS = (byte) 0xA0;
    private static final byte INS_VERIFY_PIN = (byte) 0x20;
    private static final byte INS_SET_PIN = (byte) 0x21;
    private static final byte INS_WRITE_BEGIN = (byte) 0xD0;
    private static final byte INS_WRITE_CHUNK = (byte) 0xD1;
    private static final byte INS_WRITE_COMMIT = (byte) 0xD2;
    private static final byte INS_READ = (byte) 0xB0;
    private static final byte INS_WIPE = (byte) 0xE0;

    private static final byte PROTOCOL_VERSION = 1;
    private static final byte APPLET_VERSION_MAJOR = 1;
    private static final byte APPLET_VERSION_MINOR = 1;

    private static final byte FLAG_PIN_SET = 0x01;
    private static final byte FLAG_HAS_BACKUP = 0x02;
    private static final byte FLAG_PIN_BLOCKED = 0x04;
    private static final byte FLAG_PIN_VERIFIED = 0x08;

    private static final byte PIN_TRIES = 5;
    private static final byte PIN_MIN_LENGTH = 6;
    private static final byte PIN_MAX_LENGTH = 16;
    private static final short MAX_BACKUP = 2048;
    private static final short SHA256_LENGTH = 32;

    private static final short SW_WRONG_PIN_BASE = (short) 0x63C0;
    private static final short SW_PIN_BLOCKED = (short) 0x6983;
    private static final short SW_NO_BACKUP = (short) 0x6A88;
    private static final short SW_HASH_MISMATCH = (short) 0x6A80;

    private static final short WRITE_TOTAL = 0;
    private static final short WRITE_NEXT = 1;
    private static final short WRITE_STATE_LENGTH = 2;

    private final OwnerPIN pin;
    private final byte[] slotA;
    private final byte[] slotB;
    private final MessageDigest sha256;
    // Cleared on deselect and power loss, so a save has to start again after any interruption.
    private final short[] writeState;

    private boolean pinSet;
    private boolean activeIsA;
    private short backupLength;

    private KaChatNFCApplet() {
        pin = new OwnerPIN(PIN_TRIES, PIN_MAX_LENGTH);
        slotA = new byte[MAX_BACKUP];
        slotB = new byte[MAX_BACKUP];
        sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        writeState = JCSystem.makeTransientShortArray(WRITE_STATE_LENGTH, JCSystem.CLEAR_ON_DESELECT);
        activeIsA = true;
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new KaChatNFCApplet().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
    }

    public void deselect() {
        pin.reset();
    }

    public void process(APDU apdu) {
        if (selectingApplet()) {
            sendStatus(apdu);
            return;
        }
        byte[] buffer = apdu.getBuffer();
        if (buffer[ISO7816.OFFSET_CLA] != CLA) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
        switch (buffer[ISO7816.OFFSET_INS]) {
            case INS_STATUS:
                sendStatus(apdu);
                break;
            case INS_VERIFY_PIN:
                verifyPin(apdu);
                break;
            case INS_SET_PIN:
                setPin(apdu);
                break;
            case INS_WRITE_BEGIN:
                writeBegin(apdu);
                break;
            case INS_WRITE_CHUNK:
                writeChunk(apdu);
                break;
            case INS_WRITE_COMMIT:
                writeCommit(apdu);
                break;
            case INS_READ:
                read(apdu);
                break;
            case INS_WIPE:
                wipe();
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    private void sendStatus(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        byte flags = 0;
        if (pinSet) {
            flags |= FLAG_PIN_SET;
        }
        if (backupLength > 0) {
            flags |= FLAG_HAS_BACKUP;
        }
        if (pinSet && pin.getTriesRemaining() == 0) {
            flags |= FLAG_PIN_BLOCKED;
        }
        if (pin.isValidated()) {
            flags |= FLAG_PIN_VERIFIED;
        }
        short offset = 0;
        buffer[offset++] = PROTOCOL_VERSION;
        buffer[offset++] = APPLET_VERSION_MAJOR;
        buffer[offset++] = APPLET_VERSION_MINOR;
        buffer[offset++] = flags;
        buffer[offset++] = pin.getTriesRemaining();
        offset = Util.setShort(buffer, offset, MAX_BACKUP);
        apdu.setOutgoingAndSend((short) 0, offset);
    }

    private short receiveAll(APDU apdu) {
        short length = apdu.setIncomingAndReceive();
        short expected = (short) (apdu.getBuffer()[ISO7816.OFFSET_LC] & 0x00FF);
        if (length != expected) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        return length;
    }

    private void requirePin() {
        if (!pinSet) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        if (pin.getTriesRemaining() == 0) {
            ISOException.throwIt(SW_PIN_BLOCKED);
        }
        if (!pin.isValidated()) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
    }

    private void verifyPin(APDU apdu) {
        short length = receiveAll(apdu);
        if (!pinSet) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        if (pin.getTriesRemaining() == 0) {
            ISOException.throwIt(SW_PIN_BLOCKED);
        }
        if (length > PIN_MAX_LENGTH
                || !pin.check(apdu.getBuffer(), ISO7816.OFFSET_CDATA, (byte) length)) {
            byte remaining = pin.getTriesRemaining();
            if (remaining == 0) {
                ISOException.throwIt(SW_PIN_BLOCKED);
            }
            ISOException.throwIt((short) (SW_WRONG_PIN_BASE | remaining));
        }
    }

    /** Sets the PIN, once. A PIN that is set can't be changed, even after verifying it. */
    private void setPin(APDU apdu) {
        short length = receiveAll(apdu);
        if (pinSet) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        if (length < PIN_MIN_LENGTH || length > PIN_MAX_LENGTH) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        JCSystem.beginTransaction();
        pin.update(apdu.getBuffer(), ISO7816.OFFSET_CDATA, (byte) length);
        pinSet = true;
        JCSystem.commitTransaction();
    }

    private byte[] inactiveSlot() {
        return activeIsA ? slotB : slotA;
    }

    private byte[] activeSlot() {
        return activeIsA ? slotA : slotB;
    }

    private void writeBegin(APDU apdu) {
        requirePin();
        byte[] buffer = apdu.getBuffer();
        short total = Util.getShort(buffer, ISO7816.OFFSET_P1);
        if (total <= 0 || total > MAX_BACKUP) {
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        }
        Util.arrayFillNonAtomic(inactiveSlot(), (short) 0, MAX_BACKUP, (byte) 0);
        writeState[WRITE_TOTAL] = total;
        writeState[WRITE_NEXT] = 0;
    }

    private void writeChunk(APDU apdu) {
        requirePin();
        short length = receiveAll(apdu);
        byte[] buffer = apdu.getBuffer();
        short offset = Util.getShort(buffer, ISO7816.OFFSET_P1);
        if (writeState[WRITE_TOTAL] == 0 || offset != writeState[WRITE_NEXT]) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        if ((short) (offset + length) > writeState[WRITE_TOTAL]) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, inactiveSlot(), offset, length);
        writeState[WRITE_NEXT] = (short) (offset + length);
    }

    /** The data is the SHA-256 of the whole backup. It's checked before the new copy goes live. */
    private void writeCommit(APDU apdu) {
        requirePin();
        short length = receiveAll(apdu);
        short total = writeState[WRITE_TOTAL];
        if (total == 0 || writeState[WRITE_NEXT] != total) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        if (length != SHA256_LENGTH) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        byte[] buffer = apdu.getBuffer();
        // The digest overwrites the buffer, so it goes after the expected hash.
        short digestOffset = (short) (ISO7816.OFFSET_CDATA + SHA256_LENGTH);
        sha256.reset();
        sha256.doFinal(inactiveSlot(), (short) 0, total, buffer, digestOffset);
        if (Util.arrayCompare(buffer, ISO7816.OFFSET_CDATA, buffer, digestOffset, SHA256_LENGTH) != 0) {
            ISOException.throwIt(SW_HASH_MISMATCH);
        }
        byte[] previous = activeSlot();
        JCSystem.beginTransaction();
        activeIsA = !activeIsA;
        backupLength = total;
        JCSystem.commitTransaction();
        writeState[WRITE_TOTAL] = 0;
        writeState[WRITE_NEXT] = 0;
        Util.arrayFillNonAtomic(previous, (short) 0, MAX_BACKUP, (byte) 0);
    }

    private void read(APDU apdu) {
        requirePin();
        if (backupLength == 0) {
            ISOException.throwIt(SW_NO_BACKUP);
        }
        byte[] buffer = apdu.getBuffer();
        short offset = Util.getShort(buffer, ISO7816.OFFSET_P1);
        if (offset < 0 || offset > backupLength) {
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        }
        short wanted = apdu.setOutgoing();
        short available = (short) (backupLength - offset);
        short length = wanted < available ? wanted : available;
        apdu.setOutgoingLength(length);
        apdu.sendBytesLong(activeSlot(), offset, length);
    }

    private void wipe() {
        requirePin();
        JCSystem.beginTransaction();
        backupLength = 0;
        JCSystem.commitTransaction();
        writeState[WRITE_TOTAL] = 0;
        writeState[WRITE_NEXT] = 0;
        Util.arrayFillNonAtomic(slotA, (short) 0, MAX_BACKUP, (byte) 0);
        Util.arrayFillNonAtomic(slotB, (short) 0, MAX_BACKUP, (byte) 0);
    }
}
