/*
	This file is part of APFS-Wonder (apfs-fuse), a read-only implementation
	of APFS (Apple File System) for FUSE.
	SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <cstddef>
#include <cstdint>
#include <list>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <vector>

class ApfsDecompCache
{
public:
	struct CacheKey
	{
		uint64_t volume_tag;
		uint64_t ino;

		bool operator==(const CacheKey &o) const noexcept
		{
			return volume_tag == o.volume_tag && ino == o.ino;
		}
	};

	struct CacheKeyHash
	{
		size_t operator()(const CacheKey &k) const noexcept
		{
			uint64_t h = k.volume_tag ^ (k.ino * 0x9E3779B97F4A7C15ULL);
			h ^= (h >> 33);
			h *= 0xFF51AFD7ED558CCDULL;
			h ^= (h >> 33);
			return static_cast<size_t>(h);
		}
	};

	struct Stats
	{
		uint64_t hits = 0;
		uint64_t misses = 0;
		uint64_t evictions = 0;
		size_t current_bytes = 0;
		size_t max_bytes = 0;
		size_t entries = 0;
	};

	static ApfsDecompCache &Instance()
	{
		static ApfsDecompCache instance;
		return instance;
	}

	void SetMaxBytes(size_t max_bytes)
	{
		std::lock_guard<std::mutex> lock(m_mutex);
		m_max_bytes = max_bytes;
		EvictIfNeededLocked(0);
	}

	size_t GetMaxBytes() const
	{
		std::lock_guard<std::mutex> lock(m_mutex);
		return m_max_bytes;
	}

	void SetEnabled(bool enabled)
	{
		std::lock_guard<std::mutex> lock(m_mutex);
		m_enabled = enabled;
		if (!m_enabled)
			ClearLocked();
	}

	bool IsEnabled() const
	{
		std::lock_guard<std::mutex> lock(m_mutex);
		return m_enabled;
	}

	void Clear()
	{
		std::lock_guard<std::mutex> lock(m_mutex);
		ClearLocked();
	}

	void ResetStats()
	{
		std::lock_guard<std::mutex> lock(m_mutex);
		m_hits = 0;
		m_misses = 0;
		m_evictions = 0;
	}

	std::shared_ptr<const std::vector<uint8_t>> Get(uint64_t volume_tag, uint64_t ino)
	{
		std::lock_guard<std::mutex> lock(m_mutex);
		if (!m_enabled || m_max_bytes == 0)
		{
			m_misses++;
			return nullptr;
		}

		CacheKey key{volume_tag, ino};
		auto it = m_map.find(key);
		if (it == m_map.end())
		{
			m_misses++;
			return nullptr;
		}

		m_hits++;
		m_lru.splice(m_lru.begin(), m_lru, it->second.lru_it);
		return it->second.data;
	}

	void Put(uint64_t volume_tag, uint64_t ino, const std::vector<uint8_t> &data)
	{
		std::lock_guard<std::mutex> lock(m_mutex);
		if (!m_enabled || m_max_bytes == 0 || data.size() > m_max_bytes)
			return;

		CacheKey key{volume_tag, ino};
		auto it = m_map.find(key);
		if (it != m_map.end())
		{
			m_current_bytes -= it->second.data->size();
			m_lru.erase(it->second.lru_it);
			m_map.erase(it);
		}

		EvictIfNeededLocked(data.size());

		auto shared_vec = std::make_shared<std::vector<uint8_t>>(data);
		m_lru.push_front(key);
		m_map[key] = Entry{shared_vec, m_lru.begin()};
		m_current_bytes += shared_vec->size();
	}

	Stats GetStats() const
	{
		std::lock_guard<std::mutex> lock(m_mutex);
		Stats s;
		s.hits = m_hits;
		s.misses = m_misses;
		s.evictions = m_evictions;
		s.current_bytes = m_current_bytes;
		s.max_bytes = m_max_bytes;
		s.entries = m_map.size();
		return s;
	}

private:
	ApfsDecompCache()
		: m_max_bytes(128ULL * 1024ULL * 1024ULL),
		  m_current_bytes(0),
		  m_hits(0),
		  m_misses(0),
		  m_evictions(0),
		  m_enabled(true)
	{
	}

	struct Entry
	{
		std::shared_ptr<std::vector<uint8_t>> data;
		std::list<CacheKey>::iterator lru_it;
	};

	void ClearLocked()
	{
		m_map.clear();
		m_lru.clear();
		m_current_bytes = 0;
	}

	void EvictIfNeededLocked(size_t incoming_bytes)
	{
		while (!m_lru.empty() && (m_current_bytes + incoming_bytes > m_max_bytes))
		{
			const CacheKey &oldest = m_lru.back();
			auto it = m_map.find(oldest);
			if (it != m_map.end())
			{
				m_current_bytes -= it->second.data->size();
				m_map.erase(it);
				m_evictions++;
			}
			m_lru.pop_back();
		}
	}

	mutable std::mutex m_mutex;
	std::list<CacheKey> m_lru;
	std::unordered_map<CacheKey, Entry, CacheKeyHash> m_map;
	size_t m_max_bytes;
	size_t m_current_bytes;
	uint64_t m_hits;
	uint64_t m_misses;
	uint64_t m_evictions;
	bool m_enabled;
};
