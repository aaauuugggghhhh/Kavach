import os
import json
import logging
from typing import List, Dict, Any, Optional
from dotenv import load_dotenv

# Load environment variables
load_dotenv()
load_dotenv(os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))), '.env'))

try:
    from groq import Groq
except ImportError:
    Groq = None

logger = logging.getLogger("KavachDetonator")

class LLMFridaSynthesizer:
    """
    Kavach LLMFrida Synthesizer:
    Static-to-Dynamic AI Frida Hook Synthesizer that inspects decompiled sinks
    (custom decryption routines, reflection callers, dynamic classloaders)
    and dynamically synthesizes production-grade Frida JavaScript interceptors.
    """

    def __init__(self, api_key: Optional[str] = None, model: str = "qwen2.5-coder-32b-instruct"):
        self.api_key = api_key or os.environ.get("GROQ_API_KEY")
        self.model = model
        self.client = None
        if self.api_key and Groq is not None:
            try:
                self.client = Groq(api_key=self.api_key)
            except Exception as e:
                logger.warning(f"[LLMFrida] Failed to initialize Groq client: {e}")

    def generate_hooks_from_sinks(
        self,
        sinks: Optional[List[Dict[str, Any]]] = None,
        package_name: str = "com.target.malware"
    ) -> str:
        """
        Synthesizes Frida JavaScript interceptor code for targeted static sinks.
        Falls back to robust, deterministic Frida hook templates if the API is offline.
        """
        if not sinks:
            sinks = [
                {
                    "class": "javax.crypto.Cipher",
                    "method": "doFinal",
                    "reason": "Cryptographic payload decryption"
                },
                {
                    "class": "dalvik.system.DexClassLoader",
                    "method": "<init>",
                    "reason": "Dynamic secondary payload loading"
                },
                {
                    "class": "java.lang.reflect.Method",
                    "method": "invoke",
                    "reason": "Reflective execution of concealed methods"
                }
            ]

        if self.client:
            try:
                logger.info(f"[LLMFrida] Prompting Groq ({self.model}) for {len(sinks)} static sinks...")
                prompt = self._build_prompt(sinks, package_name)
                
                completion = self.client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {
                            "role": "system",
                            "content": (
                                "You are an elite reverse engineer and Frida script synthesizer for Android malware analysis. "
                                "Your goal is to write clean, crash-resilient Frida JavaScript hooks for Android ART Dalvik runtimes. "
                                "Requirements:\n"
                                "1. Wrap all hooks strictly inside Java.perform(function() { ... }).\n"
                                "2. Enclose every hook implementation in try/catch blocks so one failing hook never crashes the process.\n"
                                "3. Use console.log('[LLM-Frida-Hook] ...') to log method arguments, return values, and decrypted strings.\n"
                                "4. Output ONLY valid raw JavaScript code without markdown code blocks, explanations, or commentary."
                            )
                        },
                        {
                            "role": "user",
                            "content": prompt
                        }
                    ],
                    temperature=0.1,
                    max_tokens=1500
                )
                
                content = completion.choices[0].message.content.strip()
                # Clean up any accidental markdown formatting
                if content.startswith("```"):
                    lines = content.splitlines()
                    if lines[0].startswith("```"):
                        lines = lines[1:]
                    if lines and lines[-1].strip() == "```":
                        lines = lines[:-1]
                    content = "\n".join(lines).strip()
                    
                if "Java.perform" in content:
                    logger.info("[LLMFrida] Successfully synthesized custom AI Frida hooks via Groq Cloud.")
                    return content
                else:
                    logger.warning("[LLMFrida] Synthesized code lacked Java.perform wrapper. Falling back to robust templates.")
            except Exception as e:
                logger.warning(f"[LLMFrida] Groq API hook generation error: {e}. Utilizing deterministic template fallback.")

        return self._fallback_hooks(sinks, package_name)

    def _build_prompt(self, sinks: List[Dict[str, Any]], package_name: str) -> str:
        sinks_desc = json.dumps(sinks, indent=2)
        return (
            f"Generate targeted Frida JavaScript hooks for package '{package_name}'.\n"
            f"Target Static Sinks:\n{sinks_desc}\n\n"
            "Instructions:\n"
            "- For Cipher/decrypt methods: log the decrypted byte array converted to string or hex.\n"
            "- For DexClassLoader: log the DEX path and optimized directory.\n"
            "- For Reflection/invoke: log the target method name and declaring class.\n"
            "- Include safe null checks before inspecting objects.\n"
            "- Output RAW JavaScript ONLY."
        )

    def _fallback_hooks(self, sinks: List[Dict[str, Any]], package_name: str) -> str:
        """
        Deterministic, production-hardened Frida JavaScript fallback template.
        """
        logger.info("[LLMFrida] Building deterministic fallback dynamic interceptor script.")
        
        custom_hook_blocks = []
        for sink in sinks:
            cls = sink.get("class", "")
            method = sink.get("method", "")
            if not cls or not method:
                continue
                
            block = f"""
    // Targeted Hook: {cls}.{method} ({sink.get('reason', 'Forensic Probe')})
    try {{
        var target_{abs(hash(cls + method))} = Java.use("{cls}");
        if (target_{abs(hash(cls + method))}.{method}) {{
            var overloads = target_{abs(hash(cls + method))}.{method}.overloads;
            for (var i = 0; i < overloads.length; i++) {{
                overloads[i].implementation = function() {{
                    var argsStr = [];
                    for (var a = 0; a < arguments.length; a++) {{
                        try {{
                            if (arguments[a] !== null && arguments[a] !== undefined) {{
                                argsStr.push(arguments[a].toString());
                            }} else {{
                                argsStr.push("null");
                            }}
                        }} catch (e) {{
                            argsStr.push("<opaque>");
                        }}
                    }}
                    console.log("[LLM-Frida-Hook] Intercepted {cls}.{method}(" + argsStr.join(", ") + ")");
                    var ret = this.{method}.apply(this, arguments);
                    try {{
                        if (ret !== null && ret !== undefined) {{
                            console.log("[LLM-Frida-Hook] Returned from {cls}.{method} -> " + ret.toString());
                        }}
                    }} catch (e) {{}}
                    return ret;
                }};
            }}
        }}
    }} catch (err) {{
        // Silent catch to guarantee Dalvik VM stability
    }}
"""
            custom_hook_blocks.append(block)

        hooks_combined = "\n".join(custom_hook_blocks)

        return f"""/*
 * =========================================================================
 * Kavach LLMFrida Synthesizer (Dynamic Interceptors)
 * Target Package: {package_name}
 * =========================================================================
 */

Java.perform(function() {{
    console.log("[LLM-Frida] Initializing synthesized dynamic interceptors...");

    // 1. Universal Cryptographic Decryption Interceptor
    try {{
        var Cipher = Java.use("javax.crypto.Cipher");
        Cipher.doFinal.overload('[B').implementation = function(inputBytes) {{
            var resultBytes = this.doFinal(inputBytes);
            try {{
                var StringCls = Java.use("java.lang.String");
                var decryptedText = StringCls.$new(resultBytes);
                console.log("[LLM-Frida-Hook] Intercepted javax.crypto.Cipher.doFinal() Decrypted Plaintext: " + decryptedText);
            }} catch(e) {{
                console.log("[LLM-Frida-Hook] Intercepted javax.crypto.Cipher.doFinal() [Binary Payload, Length=" + (resultBytes ? resultBytes.length : 0) + "]");
            }}
            return resultBytes;
        }};
    }} catch(e) {{}}

    // 2. Dynamic DexClassLoader Payload Interceptor
    try {{
        var DexClassLoader = Java.use("dalvik.system.DexClassLoader");
        DexClassLoader.$init.implementation = function(dexPath, optimizedDirectory, librarySearchPath, parent) {{
            console.log("[LLM-Frida-Hook] Intercepted DexClassLoader Loading: " + dexPath + " (OptDir: " + optimizedDirectory + ")");
            return this.$init(dexPath, optimizedDirectory, librarySearchPath, parent);
        }};
    }} catch(e) {{}}

    // 3. Dynamic Reflection Invocation Interceptor
    try {{
        var Method = Java.use("java.lang.reflect.Method");
        Method.invoke.implementation = function(obj, args) {{
            var methodName = this.getName();
            var declaringClass = this.getDeclaringClass().getName();
            if (!declaringClass.startsWith("android.") && !declaringClass.startsWith("java.")) {{
                console.log("[LLM-Frida-Hook] Intercepted Dynamic Reflection -> " + declaringClass + "." + methodName + "()");
            }}
            return this.invoke(obj, args);
        }};
    }} catch(e) {{}}

{hooks_combined}
    console.log("[LLM-Frida] Synthesized dynamic interceptors active and listening.");
}});
"""

if __name__ == "__main__":
    synthesizer = LLMFridaSynthesizer()
    sample_sinks = [
        {"class": "com.malware.bankbot.CryptoUtils", "method": "decryptC2String", "reason": "C2 Domain Decryption"},
        {"class": "com.malware.bankbot.PayloadDropper", "method": "loadSecondaryDex", "reason": "Dynamic Payload Injection"}
    ]
    script = synthesizer.generate_hooks_from_sinks(sample_sinks, package_name="com.malware.bankbot")
    print(script)
