using ReedSolomon.NET;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using static KcpTransport.LowLevel.CMethods;
using IUINT16 = System.UInt16;
using IUINT32 = System.UInt32;

namespace ForwardErrorCorrection
{

    internal class ForwardErrorCorrection
    {

        internal const uint TYPE_DATA = 80;

        internal const uint TYPE_FEC = 81;

        internal const int FEC_EXPIRE_TIME = 30000;

        private List<FECPackt> recivePackts = new List<FECPackt>();

        private int _recivePacktSize;

        private int _dataShardCount;

        private int _parityShardCount;

        private int _totalShardCount;

        private IUINT32 _nextSequenceNumber;

        private readonly ReedSolomon.NET.ReedSolomon _reedSolomon;

        private uint _protectAgainstWrappedSequenceNumbers;

        private uint lastCheck;
        public ForwardErrorCorrection(int dataShardCount, int parityShardCount, int recivePacktSize)
        {
            if (dataShardCount <= 0 || parityShardCount <= 0)
            {
                throw new ArgumentException("invalid arguments");
            }
            if (recivePacktSize < dataShardCount + parityShardCount)
            {
                throw new ArgumentException("invalid arguments");
            }
            _reedSolomon = ReedSolomon.NET.ReedSolomon.Create(dataShardCount, parityShardCount);
            _dataShardCount = dataShardCount;
            _parityShardCount = parityShardCount;
            _totalShardCount = dataShardCount + parityShardCount;
            _recivePacktSize = recivePacktSize;
            _protectAgainstWrappedSequenceNumbers = (uint)((int)(0xffffffff / (uint)_totalShardCount - 1) * _totalShardCount);
        }
        public static ForwardErrorCorrection Create(int dataShardCount, int parityShardCount, int recivePacktSize)
        {
            if (dataShardCount <= 0 || parityShardCount <= 0)
            {
                throw new ArgumentException("invalid arguments");
            }
            if (recivePacktSize < dataShardCount + parityShardCount)
            {
                throw new ArgumentException("invalid arguments");
            }
            var forwardErrorCorrection = new ForwardErrorCorrection(dataShardCount, parityShardCount, recivePacktSize);

            return forwardErrorCorrection;
        }

        public unsafe static FECPackt Decode(Span<byte> span, int size)
        {

            var type = Unsafe.ReadUnaligned<ushort>(ref span[0]);

            var sequenceNumber = Unsafe.ReadUnaligned<uint>(ref span[4]);

            var totalMilliseconds = (uint)DateTime.UtcNow.Subtract(DateTime.MinValue).TotalMilliseconds;

            if (span.Length > size)
            {

                span = span.Slice(0, size);
            }

            span = span.Slice(8);

            FECPackt pkt = new FECPackt()
            {
                sequenceNumber = sequenceNumber,
                type = type,
                totalMilliseconds = totalMilliseconds,
                buffer = span.ToArray()
            };
            return pkt;
        }

        public bool isEnabled()
        {
            if (_dataShardCount > 0)
            {
                return _parityShardCount > 0;
            }
            return false;
        }

        public List<Memory<byte>> Input(FECPackt pkt)
        {
            var recovered = new List<Memory<byte>>();
            uint now = (uint)DateTime.UtcNow.Subtract(DateTime.MinValue).TotalMilliseconds;
            if (now - lastCheck >= FEC_EXPIRE_TIME)
            {
                List<FECPackt> removePkts = new List<FECPackt>();
                for (int i = 0; i < recivePackts.Count; i++)
                {
                    FECPackt fecPkt = recivePackts[i];
                    if (now - fecPkt.totalMilliseconds > FEC_EXPIRE_TIME)
                    {
                        removePkts.Add(fecPkt);
                    }
                }
                for (int j = 0; j < removePkts.Count; j++)
                {
                    recivePackts.Remove(removePkts[j]);
                }
                lastCheck = now;
            }
            // insertion
            int count = recivePackts.Count - 1;
            int insertIdx = 0;
            for (int i = count; i >= 0; i--)
            {
                if (pkt.sequenceNumber == recivePackts[i].sequenceNumber)
                {
                    return recovered;
                }
                if (pkt.sequenceNumber > recivePackts[i].sequenceNumber)
                {
                    insertIdx = i + 1;
                    break;
                }
            }
            // insert into ordered rx queue
            recivePackts.Insert(insertIdx, pkt);
            // shard range for current packet
            var shardBegin = pkt.sequenceNumber - pkt.sequenceNumber % _totalShardCount;
            var shardEnd = shardBegin + _totalShardCount - 1;
            // max search range in ordered queue for current shard
            int searchBegin = insertIdx - (int)(pkt.sequenceNumber % _totalShardCount);
            if (searchBegin < 0)
            {
                searchBegin = 0;
            }

            int searchEnd = searchBegin + _totalShardCount - 1;

            if (searchEnd >= recivePackts.Count)
            {
                searchEnd = recivePackts.Count - 1;
            }
            if (searchEnd > searchBegin && searchEnd - searchBegin + 1 >= _dataShardCount)
            {
                int shardCount = 0;
                int dataShardCount = 0;
                int first = 0;
                int byteCount = 0;
                var shardBuffers = new List<Memory<byte>>(new Memory<byte>[_totalShardCount]);
                var shardPresent = new List<bool>(new bool[_totalShardCount]);
                for (int k = searchBegin; k <= searchEnd; k++)
                {
                    uint seqid = recivePackts[k].sequenceNumber;
                    if (seqid > shardEnd)
                    {
                        break;
                    }
                    if (seqid >= shardBegin)
                    {
                        var idx = (int)(seqid % _totalShardCount);
                        shardBuffers[idx] = recivePackts[k].buffer.ToArray();
                        shardPresent[idx] = true;
                        shardCount++;
                        if (recivePackts[k].type == TYPE_DATA)
                        {
                            dataShardCount++;
                        }
                        if (shardCount == 1)
                        {
                            first = k;
                        }
                        if (recivePackts[k].buffer.Length > byteCount)
                        {
                            byteCount = recivePackts[k].buffer.Length;
                        }
                    }
                }
                if (dataShardCount == _dataShardCount)
                {
                    // no lost
                    recivePackts.RemoveRange(first, shardCount);
                }
                else if (shardCount >= _dataShardCount)
                {
                    // recoverable
                    // equally resized
                    for (int l = 0; l < shardBuffers.Count; l++)
                    {
                        if (!shardBuffers[l].IsEmpty)
                        {
                            byte[] array = shardBuffers[l].ToArray();
                            Array.Resize(ref array, byteCount);
                            shardBuffers[l] = new Memory<byte>(array);
                        }
                        else {
                            shardBuffers[l] = new byte[byteCount];
                        }
                    }
                    byte[][] shards = shardBuffers
                                    .Select(memory => memory.ToArray())
                                    .ToArray();
                    // reconstruct shards
                    _reedSolomon.DecodeMissing(shards, shardPresent.ToArray(), 0, byteCount);
                    shardBuffers = shards.Select(shard => shard.AsMemory()).ToList();
                    for (int m = 0; m < _dataShardCount; m++)
                    {
                        if (!shardPresent[m])
                        {
                            recovered.Add(shardBuffers[m]);
                        }
                    }
                    recivePackts.RemoveRange(first, shardCount);
                }
            }
            if (recivePackts.Count > _recivePacktSize)
            {
                recivePackts.RemoveAt(0);
            }
            return recovered;
        }

        public void Encode(ref List<Memory<byte>> shardBuffers)
        {
            int byteCount = shardBuffers.Max(buffer => buffer.Length);
            for (int j = 0; j < shardBuffers.Count; j++)
            {
                var buffers = shardBuffers[j];
                if (buffers.Length < byteCount)
                {
                    var bytes = new byte[byteCount];
                    var merory = bytes.AsMemory();
                    buffers.CopyTo(merory);
                    shardBuffers[j] = merory;
                }
            }

            byte[][] shards = shardBuffers
                .Select(memory => memory.ToArray())
                .ToArray();

            _reedSolomon.EncodeParity(shards, 0, byteCount);
            shardBuffers = shards.Select(shard => shard.AsMemory()).ToList();
        }

        internal unsafe void MarkData(Span<byte> span, ushort size)
        {
            Unsafe.WriteUnaligned(ref span[0], TYPE_DATA);
            Unsafe.WriteUnaligned(ref span[4], _nextSequenceNumber);
            Unsafe.WriteUnaligned(ref span[8], (short)(size + 2));
            _nextSequenceNumber++;
        }

        internal unsafe void MarkFEC(Span<byte> span)
        {
            Unsafe.WriteUnaligned(ref span[0], TYPE_FEC);
            Unsafe.WriteUnaligned(ref span[4], _nextSequenceNumber);
            _nextSequenceNumber++;
            if (_nextSequenceNumber >= _protectAgainstWrappedSequenceNumbers)
            {
                _nextSequenceNumber = 0u;
            }
        }

    }
    internal struct FECPackt
    {
        public uint sequenceNumber;

        public ushort type;

        public ReadOnlyMemory<byte> buffer;

        public uint totalMilliseconds;
    }
}
