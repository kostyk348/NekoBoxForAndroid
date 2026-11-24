package io.nekohasekai.sagernet.bg

import android.content.Context
import io.nekohasekai.sagernet.ktx.Logs
import java.io.File

/**
 * Hedge — локальный SOCKS5-туннель, который повторяет оборванное TLS-рукопожатие:
 * буферизует клиентские байты и переподключается, пока сервер не ответит первым байтом.
 * Используется профилем SOCKS 127.0.0.1:7891 (см. README раздел Hedge).
 *
 * Бинарник пакуется как jniLibs/arm64-v8a/libhedge.so и исполняется из nativeLibraryDir
 * (Android 10+ запрещает exec из data-каталога, nativeLibraryDir разрешён).
 */
object HedgeRunner {

    const val PORT = 7891

    @Volatile
    private var process: Process? = null

    @Synchronized
    fun start(context: Context) {
        if (process != null) return
        try {
            val bin = File(context.applicationInfo.nativeLibraryDir, "libhedge.so")
            if (!bin.exists()) {
                Logs.w("hedge: binary missing in nativeLibraryDir")
                return
            }
            val log = File(context.cacheDir, "hedge.log")
            process = ProcessBuilder(
                bin.absolutePath,
                "--socks5", "127.0.0.1:$PORT",
                "--retries", "6",
            ).redirectErrorStream(true).start()
            val proc = process
            Thread {
                try {
                    proc?.inputStream?.bufferedReader()?.useLines { lines ->
                        log.outputStream().use { out ->
                            out.bufferedWriter().use { w ->
                                lines.forEach { w.write(it + "\n"); w.flush() }
                            }
                        }
                    }
                } catch (_: Exception) {
                }
            }.apply { isDaemon = true }.start()
            Logs.i("hedge: started on 127.0.0.1:$PORT (pid ${proc?.pid()}, log ${log.absolutePath})")
        } catch (e: Exception) {
            Logs.w("hedge: start failed: $e")
            process = null
        }
    }

    @Synchronized
    fun stop() {
        val proc = process
        process = null
        if (proc != null) {
            proc.destroy()
            Logs.i("hedge: stopped")
        }
    }
}
