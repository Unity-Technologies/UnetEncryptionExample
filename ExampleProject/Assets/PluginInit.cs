using System.Collections;
using System.Collections.Generic;
using UnityEngine;
using UnityEngine.Networking;
using System.Linq;

using System.Runtime.InteropServices;
using AOT;

public class PluginInit : MonoBehaviour {


	[SerializeField]
	private int m_waitFrames;

	[System.Serializable]
	public class KeySet
	{
		public string uuid;
		public string key;
		public string iv;
		public string hmac_key;
	}

	[SerializeField]
	private KeySet[] m_keys;

	public IEnumerable<KeySet> KeySets { get { return m_keys; } }


	[DllImport("UnetEncryption")]
	private static extern int UnetEncryptionInit();

	[DllImport("UnetEncryption")]
	private static extern int AddConnectionKeys(
		string uuid_str,
		byte[] encryption_key,
		uint encryption_key_length,
		byte[] hmac_key,
		uint hmac_key_length,
		byte[] iv,
		uint iv_length);

	[DllImport("UnetEncryption")]
	private static extern int RemoveConnectionKeys(
		string uuid_str);


	private delegate void LogFunc(string s);

	[DllImport("UnetEncryption")]
	private static extern void SetLogFunc(LogFunc f);


	private IEnumerator Start()
	{
		// e.g. let applogontext awake
		for (int i = 0; i < m_waitFrames; ++i)
			yield return null;


		int err = 0;

		err = UnetEncryptionInit();
		Debug.Assert(err == 0);

		SetLogFunc(LogCB);
		Debug.Assert(err == 0);

		foreach (KeySet k in KeySets) {
			byte[] enc = System.Convert.FromBase64String(k.key);
			byte[] iv = System.Convert.FromBase64String(k.iv);
			byte[] hmac_key = System.Convert.FromBase64String(k.hmac_key);

			Debug.LogFormat("Key {0} has hmac key {1}", k.uuid, string.Join(", ", hmac_key.Select(x => ((int)x).ToString("x")).ToArray()));

			Debug.LogFormat("Lengths {0} {1} {2}", enc.Length, hmac_key.Length, iv.Length);

			err = AddConnectionKeys(k.uuid, enc, (uint)enc.Length, hmac_key, (uint)hmac_key.Length, iv, (uint)iv.Length);
			Debug.AssertFormat(err == 0, "Failed to add key: {0}", err);
		}


		NetworkTransport.Init();

		string dll_ext = "";
		string extra_path = "";
		string lib_prefix = "";
		RuntimePlatform platform = Application.platform;
		switch (platform) {
			case RuntimePlatform.LinuxEditor:
			case RuntimePlatform.LinuxPlayer:
				extra_path = "x86_64";
				dll_ext = "so";
				lib_prefix = "lib";
				break;
			case RuntimePlatform.WindowsEditor:
			case RuntimePlatform.WindowsPlayer:
			case RuntimePlatform.XboxOne:
				dll_ext = "dll";
				break;
		}

		string path = string.Format("{0}/Plugins/{1}/{2}UnetEncryption.{3}", Application.dataPath, extra_path, lib_prefix, dll_ext);

		Debug.LogFormat("Attempting to load \"{0}\"", path);
		
		bool loadedOk = UnityEngine.Networking.NetworkTransport.LoadEncryptionLibrary(path);
		Debug.Assert(loadedOk, "Failed to call LoadEncryptionLibrary.");

		Debug.LogFormat("Plugin initted.");
	}



	private static List<string> s_lines = new List<string>();

	[MonoPInvokeCallback(typeof(LogFunc))]
	private static void LogCB (string s)
	{
		lock (s_lines) {
			s_lines.Add(s);
		}
	}


	private void Update()
	{
		lock (s_lines) {
			foreach (string s in s_lines) {
				Debug.LogFormat ("Native> {0}", s);
			}
			s_lines.Clear();
		}
	}

}
