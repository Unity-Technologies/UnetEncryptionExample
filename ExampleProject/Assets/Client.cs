using System.Collections;
using System.Collections.Generic;
using UnityEngine;
using UnityEngine.Networking;
using System.Linq;

using System.Runtime.InteropServices;

public class Client : MonoBehaviour {



	[SerializeField]
	private string m_serverAddr;

	[SerializeField]
	private int m_serverPort;


	private int m_serverHost, m_connectionId;

	public bool IsConnected { get; private set; }


	[DllImport("UnetEncryption")]
	private static extern int SetUuidForNextConnection(string uuid_str);




	public void Setup (string key_uuid)
	{
		SetUuidForNextConnection(key_uuid);
	}

	// Use this for initialization
	IEnumerator Start () {

		ConnectionConfig config = new ConnectionConfig();

		config.AddChannel(QosType.Unreliable);
		config.PacketSize = 1000;

		Debug.LogFormat("Default config has {0} channels", config.ChannelCount);
		HostTopology top = new HostTopology(config, 10);

		int serverHostId = NetworkTransport.AddHost(top);

		byte err = 0;
		Debug.LogFormat("Client connecting...");




		NetworkTransport.Connect(serverHostId, m_serverAddr, m_serverPort, 0, out err);

		StartCoroutine(SendReceive());
		StartCoroutine(SendTime());

		yield break;
	}


	IEnumerator SendReceive ()
	{
		byte[] buffer = new byte[(64 * 1024) - 1];


		while (true) {

			yield return null;

			int host = 0;
			int connection = 0;
			int channel = 0;
			int size = 0;
			byte err = 0;

			NetworkEventType evt = NetworkTransport.Receive(out host, out connection, out channel, buffer, buffer.Length, out size, out err);

			if (err != 0) {
				Debug.LogWarningFormat("SendReceive on client failed with {0}", err);
				continue;
			}

			switch (evt) {

				case NetworkEventType.ConnectEvent:
					Debug.LogFormat("Connected as client with connection id {0}.  Server is host {1}", connection, host);
					m_serverHost = host;
					m_connectionId = connection;
					IsConnected = true;
					break;

				case NetworkEventType.DisconnectEvent:
					Debug.LogFormat("Lost connection to server.");
					IsConnected = false;
					break;

				case NetworkEventType.DataEvent:
					string s = System.Text.Encoding.UTF8.GetString(buffer, 0, size);
					Debug.LogFormat(
						"Client receives message from host {0} on connection {1} channel {2} said: \"{3}\"", host, connection, channel, s);
					break;

			}
		}
	}


	IEnumerator SendTime ()
	{
		while (true) {
			yield return new WaitForSeconds(5.0f);
			if (!IsConnected)
				continue;


			System.DateTime now = System.DateTime.Now;

			string s = string.Format("I am the client and I think the time is \"{0}\"", now);

			byte[] buffer = System.Text.Encoding.UTF8.GetBytes(s);
			byte err = 0;

			NetworkTransport.Send(m_serverHost, m_connectionId, 0, buffer, buffer.Length, out err);

			if (err != 0) {
				Debug.LogWarning("Client failed to send time.");
			}
		}
	}

}
