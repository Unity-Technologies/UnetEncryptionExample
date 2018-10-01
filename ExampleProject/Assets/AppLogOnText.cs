using System.Collections;
using System.Collections.Generic;
using UnityEngine;
using UnityEngine.UI;
using System.IO;

public class AppLogOnText : MonoBehaviour {


	private List<string> m_lines = new List<string>();

	[SerializeField]
	private Text m_text;

	[SerializeField]
	private int m_capacity;

	void Awake ()
	{
		Application.logMessageReceived += Log;
	}


	private void Log (string condition, string stackTrace, LogType type)
	{
		using (TextReader r = new StringReader (condition)) {
			while (true) {
				string s = r.ReadLine ();
				if (s == null)
					break;
				m_lines.Add (s);
			}
		}

		int overflow = m_lines.Count - m_capacity;
		if (overflow > 0)
			m_lines.RemoveRange (0, overflow);

		m_text.text = string.Join ("\n", m_lines.ToArray ());
	}
}
