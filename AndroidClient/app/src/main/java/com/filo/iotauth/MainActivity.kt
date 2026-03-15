package com.filo.iotauth

import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import android.util.Base64
import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import okhttp3.*
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.io.IOException
import java.util.concurrent.Executor

class MainActivity : AppCompatActivity() {

    // ==========================================
    // JNI 接口声明
    // ==========================================
    external fun initDevice(uid: String, path: String): Boolean
    external fun generateRegisterPayload(pwd: String): String
    external fun processAuthChallenge(uid: String, pwd: String, dhpubSBase64: String, serverSigMBase64: String, isBioSuccess: Boolean): String
    external fun processServerResponse(jsonResponse: String): Boolean
    external fun finalizeAuth(tagSBase64: String, serverSigTagBase64: String): Boolean
    external fun encryptCommand(plaintextCmd: String): String
    external fun decryptResponse(ciphertextB64: String): String

    // ==========================================
    // 类成员变量 (全局UI控件与状态)
    // ==========================================
    private lateinit var executor: Executor
    private lateinit var biometricPrompt: BiometricPrompt
    private lateinit var promptInfo: BiometricPrompt.PromptInfo

    // UI 控件
    private lateinit var etUid: EditText
    private lateinit var etPassword: EditText
    private lateinit var tvResult: TextView
    private lateinit var layoutLogin: LinearLayout  // 【修改点】登录页大盒子
    private lateinit var layoutControl: LinearLayout // 【修改点】控制页大盒子

    // 设备控制状态
    private var doorStatus = false
    private var lightStatus = false
    private var acStatus = false
    private var acTemp = 24
    private var acMode = "cool"

    // 网络状态
    private val client = OkHttpClient()
    private var webSocket: WebSocket? = null

    // 请确保这里的 IP 是你宿主机的局域网 IP
    private val SERVER_IP = "192.168.1.100"
    private val HTTP_REGISTER_URL = "http://$SERVER_IP:8081/api/register"
    private val WS_AUTH_URL = "ws://$SERVER_IP:8081/ws/auth"

    // 定义当前操作状态，用于区分指纹验证后的回调逻辑
    enum class ActionType { NONE, REGISTER, AUTHENTICATE }
    private var currentAction = ActionType.NONE

    // 用于暂存 WebSocket 收到的挑战参数，等待指纹验证后使用
    private var pendingDhpubS = ""
    private var pendingServerSigM = ""

    // ==========================================
    // Kotlin 层的底座安全防线：ECDSA 验签
    // ==========================================
    @Suppress("unused")
    fun verifySignatureInJava(pkBase64: String, messageBase64: String, signatureBase64: String): Boolean {
        return try {
            val pkBytes = Base64.decode(pkBase64, Base64.DEFAULT)
            val keySpec = X509EncodedKeySpec(pkBytes)
            val keyFactory = KeyFactory.getInstance("EC")
            val publicKey = keyFactory.generatePublic(keySpec)

            val messageBytes = Base64.decode(messageBase64, Base64.DEFAULT)
            val signatureBytes = Base64.decode(signatureBase64, Base64.DEFAULT)

            val signature = Signature.getInstance("SHA256withECDSA")
            signature.initVerify(publicKey)
            signature.update(messageBytes)

            val isSuccess = signature.verify(signatureBytes)
            println("======> Kotlin 层验签结果: $isSuccess <======")
            isSuccess
        } catch (e: Exception) {
            println("======> Kotlin 层验签抛出异常: ${e.message} <======")
            e.printStackTrace()
            false
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        // 1. 绑定 UI 控件到全局变量
        etUid = findViewById(R.id.etUid)
        etPassword = findViewById(R.id.etPassword)
        tvResult = findViewById(R.id.tvResult)

        // 绑定两个用于视图切换的大盒子
        layoutLogin = findViewById(R.id.layoutLogin)
        layoutControl = findViewById(R.id.layoutControl)

        val btnRegister = findViewById<Button>(R.id.btnRegister)
        val btnAuth = findViewById<Button>(R.id.btnAuth)
        val btnToggleDoor = findViewById<Button>(R.id.btnToggleDoor)
        val btnToggleLight = findViewById<Button>(R.id.btnToggleLight)
        val btnAcPower = findViewById<Button>(R.id.btnAcPower)
        val btnAcTempUp = findViewById<Button>(R.id.btnAcTempUp)
        val btnAcTempDown = findViewById<Button>(R.id.btnAcTempDown)
        val btnLogout = findViewById<Button>(R.id.btnLogout) // 【新增】退出登录按钮
        val btnAcMode = findViewById<Button>(R.id.btnAcMode) // 【新增】绑定模式切换按钮
        // ==========================================
        // 【新增】：退出登录逻辑
        // ==========================================
        btnLogout.setOnClickListener {
            // 1. 断开 WebSocket 安全隧道
            webSocket?.close(1000, "User logged out")
            webSocket = null

            // 2. 清除本地业务状态
            doorStatus = false
            lightStatus = false
            acStatus = false
            currentAction = ActionType.NONE

            // 3. 视图切换：隐藏控制台，显示登录页
            layoutControl.visibility = View.GONE
            layoutLogin.visibility = View.VISIBLE

            tvResult.text = "🔴 已安全退出登录，加密连接已销毁。\n等待操作..."
        }

        // 2. 初始化指纹 TEE 环境
        executor = ContextCompat.getMainExecutor(this)
        biometricPrompt = BiometricPrompt(this, executor,
            object : BiometricPrompt.AuthenticationCallback() {

                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    super.onAuthenticationSucceeded(result)
                    if (currentAction == ActionType.REGISTER) {
                        tvResult.text = "TEE 硬件指纹验证通过。\n正在生成底层注册载荷...\n"
                        val pwd = etPassword.text.toString()
                        val payloadJson = generateRegisterPayload(pwd)

                        if (payloadJson.startsWith("{\"error\"")) {
                            tvResult.append("\n底层执行异常: $payloadJson")
                            return
                        }
                        tvResult.append("\n载荷生成成功，正在通过 HTTP 发送至网关...")
                        sendRegistrationRequest(payloadJson)

                    } else if (currentAction == ActionType.AUTHENTICATE) {
                        tvResult.append("\nTEE 硬件指纹验证通过(注入极小噪声)。\n正在计算挑战响应...")
                        executeAuthResponse(true, etUid.text.toString(), etPassword.text.toString())
                    }
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    super.onAuthenticationError(errorCode, errString)
                    if (currentAction == ActionType.AUTHENTICATE) {
                        tvResult.append("\n指纹错误或取消验证(注入极大噪声)。\n模拟被黑客攻击...")
                        executeAuthResponse(false, etUid.text.toString(), etPassword.text.toString())
                    } else {
                        tvResult.text = "指纹验证终止: $errString"
                    }
                }

                override fun onAuthenticationFailed() {
                    super.onAuthenticationFailed()
                    Toast.makeText(applicationContext, "指纹验证未通过，请重试", Toast.LENGTH_SHORT).show()
                }
            })

        promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("设备安全授权")
            .setSubtitle("请验证设备管理员指纹")
            .setNegativeButtonText("取消/模拟验证失败")
            .build()

        // 3. 绑定主流程按钮逻辑
        btnRegister.setOnClickListener {
            val uid = etUid.text.toString()
            if (uid.isEmpty()) return@setOnClickListener Toast.makeText(this, "UID 不能为空", Toast.LENGTH_SHORT).show()

            if (!initDeviceInstance(uid)) return@setOnClickListener

            currentAction = ActionType.REGISTER
            tvResult.text = "正在请求注册...\n等待指纹授权..."
            biometricPrompt.authenticate(promptInfo)
        }

        btnAuth.setOnClickListener {
            val uid = etUid.text.toString()
            val pwd = etPassword.text.toString()
            if (uid.isEmpty() || pwd.isEmpty()) return@setOnClickListener Toast.makeText(this, "UID或密码为空", Toast.LENGTH_SHORT).show()

            if (!initDeviceInstance(uid)) return@setOnClickListener

            currentAction = ActionType.AUTHENTICATE
            tvResult.text = "正在连接网关建立 WebSocket..."
            startWebSocketAuth(uid)
        }

        // 4. 绑定 IoT 业务控制按钮逻辑
        btnToggleDoor.setOnClickListener {
            doorStatus = !doorStatus
            sendSecureCommand("door", if (doorStatus) "unlock" else "lock")
        }

        btnToggleLight.setOnClickListener {
            lightStatus = !lightStatus
            sendSecureCommand("light", if (lightStatus) "turn_on" else "turn_off")
        }

        btnAcPower.setOnClickListener {
            acStatus = !acStatus
            sendSecureCommand("ac", "sync_state", mapOf("power" to acStatus, "mode" to acMode, "temp" to acTemp))
        }

        btnAcTempUp.setOnClickListener {
            if (acStatus && acTemp < 30) {
                acTemp++
                sendSecureCommand("ac", "sync_state", mapOf("power" to true, "mode" to acMode, "temp" to acTemp))
            }
        }

        btnAcTempDown.setOnClickListener {
            if (acStatus && acTemp > 16) {
                acTemp--
                sendSecureCommand("ac", "sync_state", mapOf("power" to true, "mode" to acMode, "temp" to acTemp))
            }
        }
        btnAcMode.setOnClickListener {
            if (!acStatus) {
                Toast.makeText(this, "请先打开空调电源", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }
            // 切换状态: cool -> heat, heat -> cool
            acMode = if (acMode == "cool") "heat" else "cool"

            // 发送加密指令
            sendSecureCommand("ac", "sync_state", mapOf("power" to true, "mode" to acMode, "temp" to acTemp))

            // 顺便更新一下按钮文字，让用户知道当前处于什么模式
            btnAcMode.text = if (acMode == "cool") "❄️ 切至制热" else "☀️ 切至制冷"
        }
    }

    // ==========================================
    // 引擎初始化与核心网络流转
    // ==========================================

    private fun initDeviceInstance(uid: String): Boolean {
        val storagePath = applicationContext.filesDir.absolutePath
        val initSuccess = initDevice(uid, storagePath)
        if (!initSuccess) {
            tvResult.text = "C++ 引擎初始化失败，请检查 JNI 层。"
        }
        return initSuccess
    }

    private fun sendRegistrationRequest(jsonPayload: String) {
        val requestBody = jsonPayload.toRequestBody("application/json; charset=utf-8".toMediaType())
        val request = Request.Builder().url(HTTP_REGISTER_URL).post(requestBody).build()

        client.newCall(request).enqueue(object : Callback {
            override fun onFailure(call: Call, e: IOException) {
                runOnUiThread { tvResult.append("\n\n注册网络请求失败: ${e.message}") }
            }
            override fun onResponse(call: Call, response: Response) {
                val responseData = response.body?.string() ?: ""
                runOnUiThread {
                    if (response.isSuccessful && processServerResponse(responseData)) {
                        tvResult.append("\n\n✅ 注册闭环完成！服务器公钥已安全落盘。")
                    } else {
                        tvResult.append("\n\n❌ 注册失败或底层处理异常: $responseData")
                    }
                }
            }
        })
    }

    private fun startWebSocketAuth(uid: String) {
        val request = Request.Builder().url(WS_AUTH_URL).build()

        webSocket = client.newWebSocket(request, object : WebSocketListener() {
            override fun onOpen(webSocket: WebSocket, response: Response) {
                val authReq = JSONObject().apply {
                    put("type", "auth_request")
                    put("uid", uid)
                }
                webSocket.send(authReq.toString())
                runOnUiThread { tvResult.append("\n\n已发送 auth_request，等待挑战...") }
            }

            override fun onMessage(webSocket: WebSocket, text: String) {
                val json = JSONObject(text)
                when (json.getString("type")) {
                    "system_reset" -> {
                        runOnUiThread {
                            tvResult.append("\n\n⚠️ 收到网关广播：系统已重置！\n正在销毁本地安全连接并退回首页...")

                            // 1. 断开 WebSocket 安全隧道
                            this@MainActivity.webSocket?.close(1000, "Server Force Reset")
                            this@MainActivity.webSocket = null
                            // 2. 清理业务状态
                            doorStatus = false
                            lightStatus = false
                            acStatus = false
                            currentAction = ActionType.NONE

                            // 3. 视图切换：隐藏控制台，强制显示登录页
                            layoutControl.visibility = View.GONE
                            layoutLogin.visibility = View.VISIBLE

                            Toast.makeText(this@MainActivity, "网关数据库已清空，设备被强制下线", Toast.LENGTH_LONG).show()
                        }
                    }
                    "auth_challenge" -> {
                        pendingDhpubS = json.getString("dhpubS")
                        pendingServerSigM = json.getString("serversigm")
                        runOnUiThread {
                            tvResult.append("\n收到挑战包，唤起 TEE 验证...")
                            biometricPrompt.authenticate(promptInfo)
                        }
                    }

                    "auth_confirmation" -> {
                        val success = json.getBoolean("success")
                        runOnUiThread {
                            if (success) {
                                val tagS = json.getString("tagS")
                                val serverSigTag = json.getString("serversigtag")

                                val isFinalVerified = finalizeAuth(tagS, serverSigTag)

                                if (isFinalVerified) {
                                    tvResult.append("\n\n✅ 双向认证成功！会话密钥协商完毕。")
                                    // 【修改点】：认证成功，隐藏登录页，显示控制页
                                    layoutLogin.visibility = View.GONE
                                    layoutControl.visibility = View.VISIBLE
                                } else {
                                    tvResult.append("\n\n❌ 严重警告：网关签名伪造！可能遭遇中间人攻击。")
                                }
                            } else {
                                tvResult.append("\n\n❌ 认证被网关拒绝：密码错误或模糊提取失败。")
                            }
                        }
                    }

                    "command_result" -> {
                        val payloadB64 = json.getString("payload")
                        val plaintextFeedback = decryptResponse(payloadB64)

                        runOnUiThread {
                            if (plaintextFeedback.isNotEmpty()) {
                                tvResult.append("\n✅ 收到网关加密回执: $plaintextFeedback")
                            } else {
                                tvResult.append("\n🛑 警报：解密网关回执失败！可能遭遇重放攻击或数据篡改。")
                            }
                        }
                    }
                }
            }

            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                runOnUiThread { tvResult.append("\n\nWebSocket 异常中断: ${t.message}") }
            }
        })
    }

    private fun executeAuthResponse(isBioSuccess: Boolean, uid: String, pwd: String) {
        val responseJsonStr = processAuthChallenge(uid, pwd, pendingDhpubS, pendingServerSigM, isBioSuccess)
        val responseJson = JSONObject(responseJsonStr).apply {
            put("type", "auth_response")
        }
        webSocket?.send(responseJson.toString())
        tvResult.append("\n响应已发出，等待服务器鉴权...")
    }

    // ==========================================
    // 业务层：发送 AEAD 加密指令
    // ==========================================
    private fun sendSecureCommand(device: String, action: String, extraParams: Map<String, Any> = emptyMap()) {
        if (webSocket == null) {
            tvResult.append("\n❌ 错误：WebSocket连接已断开！")
            return
        }

        val cmdJson = JSONObject()
        cmdJson.put("device", device)
        cmdJson.put("action", action)
        for ((k, v) in extraParams) {
            cmdJson.put(k, v)
        }
        val plaintext = cmdJson.toString()

        val ciphertextB64 = encryptCommand(plaintext)
        if (ciphertextB64.isEmpty()) {
            tvResult.append("\n❌ 错误：底层加密引擎故障或未初始化！")
            return
        }

        val wsPayload = JSONObject()
        wsPayload.put("type", "secure_command")
        wsPayload.put("uid", etUid.text.toString().trim())
        wsPayload.put("command", ciphertextB64)

        tvResult.append("\n🔒 发送密文指令至网关: $plaintext")
        webSocket?.send(wsPayload.toString())
    }

    companion object {
        init {
            System.loadLibrary("iotauthclient")
        }
    }
}