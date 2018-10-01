using System.Collections;
using System.Collections.Generic;
using UnityEngine;
using System.Linq;

public class Chooser : MonoBehaviour {



	[SerializeField]
	private Client m_clientPrefab;

	[SerializeField]
	private GameObject m_serverPrefab;

	[SerializeField]
	private int m_clientIdx;

	public bool HasChosen { get; private set; }

	public void Awake()
	{
		Application.runInBackground = true;
	}

	IEnumerator Start ()
	{
		yield return new WaitForSeconds(10.0f);

		if (HasChosen)
			yield break;

		var platform = Application.platform;
		if (platform == RuntimePlatform.XboxOne)
			BeClient();
	}

	public void BeClient ()
	{
		PluginInit pi = GetComponent<PluginInit>();

		Client c = Instantiate(m_clientPrefab);

		string key_uuid = pi.KeySets.ElementAt(m_clientIdx).uuid;
		Debug.LogFormat("Client using key {0}: {1}", m_clientIdx, key_uuid);

		c.Setup(key_uuid);
	}

	public void BeServer ()
	{
		GameObject.Instantiate(m_serverPrefab);
	}
}
