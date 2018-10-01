using System.Collections;
using System.Collections.Generic;
using UnityEngine;
using UnityEngine.Networking;

public class Server : MonoBehaviour {



	struct Connection
	{
		public int host;
		public int connId;
	}

	private List<Connection> m_connections = new List<Connection>();


	// Use this for initialization
	IEnumerator Start () {

		Debug.LogFormat("Hello world, I am the server.");

		ConnectionConfig config = new ConnectionConfig ();
		config.AddChannel(QosType.Unreliable);
		config.PacketSize = 1000;


		HostTopology top = new HostTopology(config, 10);
		int me = NetworkTransport.AddHost(top, 12345);

		Debug.LogFormat("I am host {0}", me);

		StartCoroutine(SendTime());

		byte[] buf = new byte[(64 * 1024) -1];

		while (true) {

			yield return null;

			int hostId = 0;
			int connectionId = 0;
			int channel = 0;
			int size = 0;
			byte err = 0;

			NetworkEventType evt = NetworkTransport.Receive(out hostId, out connectionId, out channel, buf, buf.Length, out size, out err);

			switch (evt) {

				case NetworkEventType.Nothing:
					break;

				case NetworkEventType.ConnectEvent:
					Connection c = new Connection { host = hostId, connId = connectionId };
					m_connections.Add(c);
					Debug.LogFormat("Server got new connection id {0} from host {1}", connectionId, hostId);
					break;

				case NetworkEventType.DisconnectEvent:
					m_connections.RemoveAll(x => (x.host == hostId) && (x.connId == connectionId));
					Debug.LogFormat("Server lost connection {0} from host {1}", connectionId, hostId);
					break;

				case NetworkEventType.DataEvent:

					string s = System.Text.Encoding.UTF8.GetString(buf, 0, size);
					string mesg = string.Format("Server receives message from host {0} on conn {1} channel {2}: \"{3}\"", hostId, connectionId, channel, s);
					Debug.Log(mesg);
					break;

				default:
					break;
			}
		}
	}



	IEnumerator SendTime()
	{
		while (true) {
			yield return new WaitForSeconds(5.0f);

			if (m_connections.Count == 0)
				continue;


			System.DateTime now = System.DateTime.Now;
			string s = string.Format("I am the server and I think the time is \"{0}\"", now);

			byte[] buffer = System.Text.Encoding.UTF8.GetBytes(s);
			byte err = 0;

			foreach (var conn in m_connections) {

				NetworkTransport.Send(conn.host, conn.connId, 0, buffer, buffer.Length, out err);


				if (err != 0) {
					Debug.LogWarning("Server failed to send time.");
				}

			}





		}
	}

}
