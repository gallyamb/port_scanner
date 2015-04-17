using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using PacketDotNet;
using SharpPcap;
using SharpPcap.WinPcap;

namespace PortScanner
{
    public static class NetworkUtils
    {
        // http://www.codeproject.com/KB/IP/host_info_within_network.aspx
        [DllImport("iphlpapi.dll", ExactSpelling = true)]
        static extern int SendARP(int destIp, int srcIp, byte[] pMacAddr, ref int phyAddrLen);

        /// <summary>
        /// Gets the MAC address (<see cref="PhysicalAddress"/>) associated with the specified IP.
        /// </summary>
        /// <param name="ipAddress">The remote IP address.</param>
        /// <returns>The remote machine's MAC address.</returns>
        public static PhysicalAddress GetMacAddress(IPAddress ipAddress)
        {
            const int macAddressLength = 6;
            var length = macAddressLength;
            var macBytes = new byte[macAddressLength];
            SendARP(BitConverter.ToInt32(ipAddress.GetAddressBytes(), 0), 0, macBytes, ref length);
            return new PhysicalAddress(macBytes);
        }

        public static IPAddress GetLocalHostIP()
        {
            var strHostName = Dns.GetHostName();

            var ipEntry = Dns.GetHostEntry(strHostName);
            return ipEntry.AddressList.First(x => x.AddressFamily == AddressFamily.InterNetwork);
        }

        public static TcpPacket CreateTcpPacket(ushort sourcePort, ushort destinationPort, bool syn, bool rst)
        {
            var result = new TcpPacket(sourcePort, destinationPort) { Syn = syn, Rst = rst };

            return result;
        }

        public static IPv4Packet CreateIpV4Packet(IPAddress sourceIpAddress, IPAddress destinationIpAddress,
            TcpPacket payloadPacket)
        {
            var result = new IPv4Packet(sourceIpAddress, destinationIpAddress) { PayloadPacket = payloadPacket };

            payloadPacket.UpdateTCPChecksum();

            result.UpdateIPChecksum();
            result.UpdateCalculatedValues();

            return result;
        }

        public static EthernetPacket CreateEthernetPacket(PhysicalAddress sourceAddress,
            PhysicalAddress destinationAddress, Packet payloapPacket)
        {
            var result = new EthernetPacket(sourceAddress, destinationAddress, EthernetPacketType.IpV4)
            {
                PayloadPacket = payloapPacket
            };

            return result;
        }

        public static IPAddress ResolveHostName(string hostName)
        {
            return Dns.GetHostAddresses(hostName).First(x => x.AddressFamily == AddressFamily.InterNetwork);
        }

        public static WinPcapDevice GetActiveDevice(IPAddress localIpAddress)
        {
            return
                WinPcapDeviceList.Instance.First(
                    x => x.Interface.Addresses.Select(y => y.Addr.ipAddress).Contains(localIpAddress));
        }
    }

    static class Program
    {
        private static void Main(string[] args)
        {
            var scanner = new UdpPortScanner("google.com");
            //var scanner = new TcpSynPortScanner(args[0], int.Parse(args[1]));


            scanner.PrintOpenPorts();
            //var ports = scanner.GetOpenPorts().Result;
            //foreach (var port in ports)
            //{
            //    Console.WriteLine("Open: {0}", port);
            //}
        }
    }

    public class UdpPortScanner
    {
        private List<Socket> sockets = new List<Socket>();
        private IPAddress remoteAddress;
        private Socket socket;

        private int MaxPort
        {
            get { return (1 << 16); }
        }

        public UdpPortScanner(string hostName, int socketsCount = 1)
        {
            socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            remoteAddress = Dns.GetHostAddresses(hostName).First(x => x.AddressFamily == AddressFamily.InterNetwork);
        }

        public void PrintOpenPorts()
        {
            var icmpListener = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.Icmp);
            icmpListener.Bind(new IPEndPoint(NetworkUtils.GetLocalHostIP(), 0));
            icmpListener.IOControl(IOControlCode.ReceiveAll, new byte[] { 1, 0, 0, 0 }, new byte[] { 1, 0, 0, 0 });
            icmpListener.ReceiveTimeout = 500;

            var buffer = new byte[1 << 12];
            EndPoint remoteEndPoint = new IPEndPoint(IPAddress.Any, 0);
            for (var i = 0; i < MaxPort; i++)
            {
                socket.SendTo(new byte[0], new IPEndPoint(remoteAddress, i));
                try
                {
                    var bytesRead = icmpListener.ReceiveFrom(buffer, ref remoteEndPoint);
                    Console.WriteLine("ICMPListener received " + bytesRead + " from " + remoteEndPoint);
                }
                catch (SocketException e)
                {
                    if (e.ErrorCode == 10060)
                        continue;
                    throw;
                }
            }


            while (true)
            {
            }
            Console.ReadLine();
        }
    }

    public class TcpSynPortScanner
    {
        private enum TcpType
        {
            Syn,
            Rst
        }

        private readonly ushort localPort;
        private readonly IPAddress localIp;
        private readonly PhysicalAddress localMacAddress;

        private readonly IPAddress destinationIp;
        private readonly PhysicalAddress destinationMacAddress;

        private readonly WinPcapDevice device;

        private readonly HashSet<ushort> openPorts = new HashSet<ushort>();
        private readonly HashSet<ushort> filteredPorts = new HashSet<ushort>();

        private readonly int timeout;

        private bool shouldPrint;

        private TcpSynPortScanner(string hostName)
        {
            timeout = 5000;

            localIp = NetworkUtils.GetLocalHostIP();
            localPort = (ushort)new Random().Next(20000, 50000);

            device = NetworkUtils.GetActiveDevice(localIp);

            localMacAddress = device.Interface.MacAddress;

            destinationIp = NetworkUtils.ResolveHostName(hostName);
            var tryCount = 8;
            while (--tryCount > 0)
            {

                destinationMacAddress = NetworkUtils.GetMacAddress(destinationIp);
                if (!Equals(destinationMacAddress, new PhysicalAddress(new byte[] { 0, 0, 0, 0, 0, 0 })))
                    break;
                Thread.Sleep(500 / tryCount);
            }

            if (destinationMacAddress == null)
                throw new Exception("Destination MAC can't be null");

            device.Open(DeviceMode.Promiscuous, 100);
            ConfigureWinPcapDevice();

        }

        public TcpSynPortScanner(string hostName, int timeout)
            : this(hostName)
        {
            this.timeout = timeout;
        }

        public void PrintOpenPorts()
        {
            shouldPrint = true;
            device.StartCapture();
            var tasks = new List<Task>();
            for (ushort i = 1; i < 10000; i++)
            {
                var ethernetPacket = GenerateEthernetPacket(i, TcpType.Syn);

                var i1 = i;
                var task = Task.Run(async () =>
                {
                    var timeoutMs = 128;

                    for (var j = 0; j < 4; j++)
                    {
                        device.SendPacket(ethernetPacket);
                        if (openPorts.Contains(i1) || filteredPorts.Contains(i1))
                            return;
                        await Task.Delay(timeoutMs * j);
                    }
                });

                tasks.Add(task);
            }
            Task.WaitAll(tasks.ToArray());
            device.Close();
        }

        public async Task<IEnumerable<ushort>> GetOpenPorts()
        {
            shouldPrint = false;
            device.StartCapture();
            for (ushort i = 1; i < 65535; i++)
            {
                device.SendPacket(GenerateEthernetPacket(i, TcpType.Syn));
            }
            await Task.Delay(timeout);
            device.Close();

            return openPorts;
        }


        private void ConfigureWinPcapDevice()
        {
            device.OnPacketArrival += async (sender, eventArgs) =>
            {
                var packet = Packet.ParsePacket(eventArgs.Packet.LinkLayerType, eventArgs.Packet.Data);
                var arrivedIpPacket = packet.Extract(typeof(IpPacket)) as IPv4Packet;

                if (arrivedIpPacket == null)
                    return;

                if (!arrivedIpPacket.SourceAddress.Equals(destinationIp)) return;

                var winPcapDevice = sender as WinPcapDevice;
                if (winPcapDevice == null)
                    return;

                var arrivedTcpPacket = arrivedIpPacket.Extract(typeof(TcpPacket)) as TcpPacket;

                if (arrivedTcpPacket == null) { return; }

                var sourcePort = arrivedTcpPacket.SourcePort;
                //if (arrivedTcpPacket.Rst)
                //{
                //    Monitor.Enter(filteredPorts);
                //    if (filteredPorts.Contains(sourcePort))
                //        return;
                //    filteredPorts.Add(sourcePort);
                //    Monitor.Pulse(filteredPorts);

                //    if (shouldPrint)
                //        Console.WriteLine("Filtered: {0}", sourcePort);
                //}
                //else
                if (arrivedTcpPacket.Syn && arrivedTcpPacket.Ack)
                {
                    var newEther = GenerateEthernetPacket(sourcePort, TcpType.Rst);

                    winPcapDevice.SendPacket(newEther);

                    //var tcp = new TcpClient(new IPEndPoint(localIp, localPort));
                    //await tcp.ConnectAsync(arrivedIpPacket.SourceAddress, arrivedTcpPacket.SourcePort);
                    //tcp.ExclusiveAddressUse = false;
                    //await tcp.GetStream().WriteAsync("Which protocol?".Select(Convert.ToByte).ToArray(), 0, "Which protocol?".Length);
                    //var readStream = new MemoryStream((int) Math.Pow(2, 16));
                    //await tcp.GetStream().ReadAsync(readStream.GetBuffer(), 0, readStream.Capacity);

                    Monitor.Enter(openPorts);
                    if (openPorts.Contains(sourcePort))
                        return;
                    openPorts.Add(sourcePort);
                    Monitor.Pulse(openPorts);


                    if (shouldPrint)
                        Console.WriteLine("Open: {0}", sourcePort);
                }
            };

            device.Filter = "ip and tcp";
        }

        private enum ProtocolType
        {
            Http,
            Tcp,
            Smtp
        }

        private EthernetPacket GenerateEthernetPacket(ushort destinationPort, TcpType packetType)
        {
            TcpPacket tcpPacket;
            switch (packetType)
            {
                case TcpType.Syn:
                    tcpPacket = NetworkUtils.CreateTcpPacket(localPort, destinationPort, true, false);
                    break;
                case TcpType.Rst:
                    tcpPacket = NetworkUtils.CreateTcpPacket(localPort, destinationPort, false, true);
                    break;
                default:
                    tcpPacket = NetworkUtils.CreateTcpPacket(localPort, destinationPort, false, false);
                    break;

            }
            var ipPacket = NetworkUtils.CreateIpV4Packet(localIp, destinationIp, tcpPacket);

            return NetworkUtils.CreateEthernetPacket(localMacAddress, destinationMacAddress, ipPacket);
        }
    }
}
