import crypto from 'crypto'

import sqlite from 'better-sqlite3'
import * as cose from '../../src';

export const create_sqlite_log = (database: string) => {

  const db = new sqlite(database);

  db.prepare(`
  CREATE TABLE IF NOT EXISTS tiles 
  (id TEXT PRIMARY KEY, data BLOB);
  
  `).run()

  db.prepare(`
  CREATE TABLE IF NOT EXISTS kv 
  (key text unique, value text);
  `).run()

  const hash_size = 32
  const tile_height = 2

  const log = new cose.TileLog({
    tile_height,
    hash_size,
    read_tree_size: () => {
      const rows = db.prepare(`
        SELECT * FROM kv
        WHERE key = 'tree_size'
                `).all();
      const [row] = rows as { key: string, value: string }[]
      try {
        return parseInt(row.value, 10)
      } catch (e) {
        // console.error(e)
        return 0
      }
    },
    update_tree_size: (new_tree_size: number) => {
      try {
        db.prepare(`
      INSERT OR REPLACE INTO kv (key, value)
      VALUES( 'tree_size',	'${new_tree_size}');
              `).run()
      } catch (e) {
        // console.error(e)
        // ignore errors
      }
    },

    read_tree_root: function () {
      const rows = db.prepare(`
        SELECT * FROM kv
        WHERE key = 'tree_root'
                `).all();
      const [row] = rows as { key: string, value: string }[]
      try {
        return new Uint8Array(Buffer.from(row.value, 'hex'))
      } catch (e) {
        return null
      }
    },
    update_tree_root: (new_tree_root: Uint8Array): void => {
      try {
        db.prepare(`
      INSERT OR REPLACE INTO kv (key, value)
      VALUES( 'tree_root',	'${Buffer.from(new_tree_root).toString('hex')}');
              `).run()
      } catch (e) {
        // ignore errors
      }
    },

    read_tile: (tile: string): Uint8Array => {
      const [base_tile] = tile.split('.')
      // look for completed tiles first
      for (let i = 4; i > 0; i--) {
        const tile_path = base_tile + '.' + i
        const rows = db.prepare(`
            SELECT * FROM tiles
            WHERE id = '${tile_path}'
                    `).all();
        if (rows.length) {
          const [row] = rows as { id: string, data: Uint8Array }[]
          return row.data
        }
      }
      return new Uint8Array(32)
    },
    update_tiles: function (tile_path: string, start: number, end: number, stored_hash: Uint8Array) {
      if (end - start !== 32) {
        // this hash was an intermediate of the tile
        // so it will never be persisted
        return null
      }
      let tile_data = this.read_tile(tile_path)
      if (tile_data.length < end) {
        const expanded_tile_data = new Uint8Array(tile_data.length + 32)
        expanded_tile_data.set(tile_data)
        tile_data = expanded_tile_data
      }
      tile_data.set(stored_hash, start)
      try {
        db.prepare(`
      INSERT INTO tiles (id, data)
      VALUES( '${tile_path}',	x'${Buffer.from(tile_data).toString('hex')}');
              `).run()
      } catch (e) {
        // ignore errors
      }
      return tile_data
    },
    hash_function: (data: Uint8Array) => {
      return new Uint8Array(crypto.createHash('sha256').update(data).digest());
    },
  })

  return { db, log }
}
