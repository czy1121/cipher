package me.reezy.cosmo.cipher


/****** hex *******/

fun ByteArray.hex(): String {
    val hex = StringBuilder(size * 2)
    for (b in this) {
        if (b.toInt() and 0xff < 0x10) {
            hex.append("0")
        }
        hex.append(Integer.toHexString(b.toInt() and 0xff))
    }
    return hex.toString()
}

fun String.decodeHex(): ByteArray {
    val bytes = ByteArray(length / 2)
    var i = 0
    while (i < length) {
        bytes[i / 2] = ((Character.digit(this[i], 16) shl 4) + Character.digit(this[i + 1], 16)).toByte()
        i += 2
    }
    return bytes
}