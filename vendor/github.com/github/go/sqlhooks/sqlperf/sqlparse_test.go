package sqlperf

import (
	"reflect"
	"testing"

	sqlparser "github.com/github/go/sqlhooks/sqlperf/parser"
)

func TestParseQuery(t *testing.T) {
	tests := []struct {
		sql  string
		want *QueryInfo
	}{{
		sql:  `SELECT status FROM repository_maintenance WHERE network_id = ?`,
		want: &QueryInfo{sqlparser.StmtSelect, []string{"repository_maintenance"}},
	}, {
		sql:  `SELECT status FROM wiki_maintenance WHERE network_id = ? AND repository_id = ?`,
		want: &QueryInfo{sqlparser.StmtSelect, []string{"wiki_maintenance"}},
	}, {
		sql:  `SELECT status FROM gist_maintenance WHERE repo_name = ?`,
		want: &QueryInfo{sqlparser.StmtSelect, []string{"gist_maintenance"}},
	}, {
		sql: `
UPDATE repository_maintenance
	 SET status = 'running'
 WHERE network_id = ? AND status = 'scheduled'
 LIMIT 1
`,
		want: &QueryInfo{sqlparser.StmtUpdate, []string{"repository_maintenance"}},
	}, {
		sql: `
UPDATE wiki_maintenance
	 SET status = 'running'
 WHERE network_id = ? AND repository_id = ? AND status = 'scheduled'
 LIMIT 1
`,
		want: &QueryInfo{sqlparser.StmtUpdate, []string{"wiki_maintenance"}},
	}, {
		sql: `
UPDATE gist_maintenance
	 SET status = 'running'
 WHERE repo_name = ? AND status = 'scheduled'
 LIMIT 1
`,
		want: &QueryInfo{sqlparser.StmtUpdate, []string{"gist_maintenance"}},
	}, {
		sql:  `UPDATE repository_maintenance SET status = 'completed' WHERE status = 'running' AND network_id = ?`,
		want: &QueryInfo{sqlparser.StmtUpdate, []string{"repository_maintenance"}},
	}, {
		sql:  `UPDATE wiki_maintenance  SET status = 'completed'  WHERE status = 'running' AND network_id = ? AND repository_id = ?`,
		want: &QueryInfo{sqlparser.StmtUpdate, []string{"wiki_maintenance"}},
	}, {
		sql:  `UPDATE gist_maintenance  SET status = 'completed' WHERE status = 'running' AND repo_name = ?`,
		want: &QueryInfo{sqlparser.StmtUpdate, []string{"gist_maintenance"}},
	}, {
		sql: `
UPDATE repository_maintenance
	 SET status = ?
 WHERE network_id = ?
`,
		want: &QueryInfo{sqlparser.StmtUpdate, []string{"repository_maintenance"}},
	}, {
		sql: `
UPDATE wiki_maintenance
	 SET status = ?
 WHERE network_id = ? AND repository_id = ?
`,
		want: &QueryInfo{sqlparser.StmtUpdate, []string{"wiki_maintenance"}},
	}, {
		sql: `
UPDATE gist_maintenance
	 SET status = ?
 WHERE repo_name = ?
 `,
		want: &QueryInfo{sqlparser.StmtUpdate, []string{"gist_maintenance"}},
	}, {
		sql:  `UPDATE repository_maintenance SET incrementals = incrementals + 1 WHERE network_id = ?`,
		want: &QueryInfo{sqlparser.StmtUpdate, []string{"repository_maintenance"}},
	}, {
		sql:  `UPDATE wiki_maintenance SET incrementals = incrementals + 1 WHERE network_id = ? AND repository_id = ?`,
		want: &QueryInfo{sqlparser.StmtUpdate, []string{"wiki_maintenance"}},
	}, {
		sql:  `UPDATE gist_maintenance SET incrementals = incrementals + 1 WHERE repo_name = ?`,
		want: &QueryInfo{sqlparser.StmtUpdate, []string{"gist_maintenance"}},
	}, {
		sql: `
 INSERT INTO repository_maintenance (network_id, status, last_maintenance_at, incrementals)
 VALUES (?, 'completed', ?, 1)
 ON DUPLICATE KEY UPDATE
	 incrementals = incrementals + VALUES(incrementals)
 `,
		want: &QueryInfo{sqlparser.StmtInsert, []string{"repository_maintenance"}},
	}, {
		sql: `
 INSERT INTO wiki_maintenance (network_id, repository_id, status, last_maintenance_at, incrementals)
 VALUES (?, ?, 'completed', ?, 1)
 ON DUPLICATE KEY UPDATE
	 incrementals = incrementals + VALUES(incrementals)
 `,
		want: &QueryInfo{sqlparser.StmtInsert, []string{"wiki_maintenance"}},
	}, {
		sql: `
 INSERT INTO gist_maintenance (repo_name, status, last_maintenance_at, incrementals)
 VALUES (?, 'completed', ?, 1)
 ON DUPLICATE KEY UPDATE
	 incrementals = incrementals + VALUES(incrementals)
	 `,
		want: &QueryInfo{sqlparser.StmtInsert, []string{"gist_maintenance"}},
	}, {
		sql:  `DELETE FROM repository_maintenance WHERE network_id = ?`,
		want: &QueryInfo{sqlparser.StmtDelete, []string{"repository_maintenance"}},
	}, {
		sql:  `DELETE FROM wiki_maintenance WHERE network_id = ? AND repository_id = ?`,
		want: &QueryInfo{sqlparser.StmtDelete, []string{"wiki_maintenance"}},
	}, {
		sql:  `DELETE FROM gist_maintenance WHERE repo_name = ?`,
		want: &QueryInfo{sqlparser.StmtDelete, []string{"gist_maintenance"}},
	}, {
		sql: `
SELECT network_id, incrementals
	FROM repository_maintenance
 WHERE status IN ('completed', 'retry')
	 AND incrementals > 0
 ORDER BY last_maintenance_at ASC
 LIMIT ?
`,
		want: &QueryInfo{sqlparser.StmtSelect, []string{"repository_maintenance"}},
	}, {
		sql: `
SELECT network_id, repository_id, incrementals
	FROM wiki_maintenance
 WHERE status IN ('completed', 'retry')
	 AND incrementals > 0
 ORDER BY last_maintenance_at ASC
 LIMIT ?
`,
		want: &QueryInfo{sqlparser.StmtSelect, []string{"wiki_maintenance"}},
	}, {
		sql: `
SELECT repo_name, incrementals
	FROM gist_maintenance
 WHERE status IN ('completed', 'retry')
	 AND incrementals > 0
 ORDER BY last_maintenance_at ASC
 LIMIT ?
`,
		want: &QueryInfo{sqlparser.StmtSelect, []string{"gist_maintenance"}},
	}, {
		sql: `
SELECT DISTINCT(key_id) FROM (
		SELECT DISTINCT(key_id) FROM repository_incrementals
		UNION ALL
		SELECT DISTINCT(key_id) FROM wiki_incrementals
		UNION ALL
		SELECT DISTINCT(key_id) FROM gist_incrementals
		UNION ALL
		SELECT DISTINCT(key_id) FROM repository_bases
		UNION ALL
		SELECT DISTINCT(key_id) FROM wiki_bases
		UNION ALL
		SELECT DISTINCT(key_id) FROM gist_bases
) AS t
`,
		want: &QueryInfo{sqlparser.StmtSelect, []string{"gist_bases", "gist_incrementals", "repository_bases", "repository_incrementals", "wiki_bases", "wiki_incrementals"}},
	}, {
		sql: `
INSERT INTO repository_incrementals
	(created_at, previous_id, network_id, repository_id, path, checksum, audit_log_len, key_id)
VALUES
	(?, ?, ?, ?, ?, ?, ?, ?)
`,
		want: &QueryInfo{sqlparser.StmtInsert, []string{"repository_incrementals"}},
	}, {
		sql: `
INSERT INTO wiki_incrementals
	(created_at, previous_id, network_id, repository_id, path, checksum, audit_log_len, key_id)
VALUES
	(?, ?, ?, ?, ?, ?, ?, ?)
`,
		want: &QueryInfo{sqlparser.StmtInsert, []string{"wiki_incrementals"}},
	}, {
		sql: `
INSERT INTO gist_incrementals
	(created_at, previous_id, repo_name, path, checksum, audit_log_len, key_id)
VALUES
	(?, ?, ?, ?, ?, ?, ?)
`,
		want: &QueryInfo{sqlparser.StmtInsert, []string{"gist_incrementals"}},
	}, {
		sql: `
DELETE
	FROM repository_incrementals
 WHERE id IN (?)
`,
		want: &QueryInfo{sqlparser.StmtDelete, []string{"repository_incrementals"}},
	}, {
		sql: `
DELETE
	FROM wiki_incrementals
 WHERE id IN (?)
`,
		want: &QueryInfo{sqlparser.StmtDelete, []string{"wiki_incrementals"}},
	}, {
		sql: `
DELETE
	FROM gist_incrementals
 WHERE id IN (?)
`,
		want: &QueryInfo{sqlparser.StmtDelete, []string{"gist_incrementals"}},
	}, {
		sql: `
SELECT * FROM repository_incrementals
WHERE network_id = ? AND repository_id = ?
ORDER BY id DESC
LIMIT 1
`,
		want: &QueryInfo{sqlparser.StmtSelect, []string{"repository_incrementals"}},
	}, {
		sql: `
SELECT * FROM wiki_incrementals
WHERE network_id = ? AND repository_id = ?
ORDER BY id DESC
LIMIT 1
`,
		want: &QueryInfo{sqlparser.StmtSelect, []string{"wiki_incrementals"}},
	}, {
		sql: `
SELECT * FROM gist_incrementals
WHERE repo_name = ?
ORDER BY id DESC
LIMIT 1
`,
		want: &QueryInfo{sqlparser.StmtSelect, []string{"gist_incrementals"}},
	}, {
		sql: `
SELECT *
	FROM repository_incrementals ri
 WHERE network_id = ?
 ORDER BY repository_id ASC, id DESC
 LIMIT 1
`,
		want: &QueryInfo{sqlparser.StmtSelect, []string{"repository_incrementals"}},
	}, {
		sql: `
SELECT * FROM repository_incrementals
WHERE network_id = ?
ORDER BY id ASC
`,
		want: &QueryInfo{sqlparser.StmtSelect, []string{"repository_incrementals"}},
	}, {
		sql: `
SELECT * FROM wiki_incrementals
WHERE network_id = ? AND repository_id = ?
ORDER BY id ASC
`,
		want: &QueryInfo{sqlparser.StmtSelect, []string{"wiki_incrementals"}},
	}, {
		sql: `
SELECT * FROM gist_incrementals
WHERE repo_name = ?
ORDER BY id ASC
`,
		want: &QueryInfo{sqlparser.StmtSelect, []string{"gist_incrementals"}},
	}, {
		sql: `
SELECT * FROM repository_incrementals
WHERE network_id = ?
AND id > (SELECT incremental_id FROM repository_bases WHERE id = ?)
ORDER BY id ASC
`,
		want: &QueryInfo{sqlparser.StmtSelect, []string{"repository_bases", "repository_incrementals"}},
	}, {
		sql: `
SELECT * FROM wiki_incrementals
WHERE network_id = ? AND repository_id = ?
AND id > (SELECT incremental_id FROM wiki_bases WHERE id = ?)
ORDER BY id ASC
`,
		want: &QueryInfo{sqlparser.StmtSelect, []string{"wiki_bases", "wiki_incrementals"}},
	}, {
		sql: `
SELECT *
	FROM gist_incrementals
 WHERE repo_name = ?
	 AND id > (SELECT incremental_id FROM gist_bases WHERE id = ?)
ORDER BY id ASC
`,
		want: &QueryInfo{sqlparser.StmtSelect, []string{"gist_bases", "gist_incrementals"}},
	}, {
		sql: `
SELECT *
	FROM repository_incrementals
 WHERE network_id = ? AND repository_id = ?
	 AND id > (SELECT incremental_id FROM repository_bases WHERE id = ?)
ORDER BY id ASC
`,
		want: &QueryInfo{sqlparser.StmtSelect, []string{"repository_bases", "repository_incrementals"}},
	}, {
		sql: `
SELECT network_id, incrementals
	FROM repository_maintenance
 WHERE status IN ('completed', 'retry')
	 AND incrementals > 0
 ORDER BY incrementals DESC
 LIMIT ?
`,
		want: &QueryInfo{sqlparser.StmtSelect, []string{"repository_maintenance"}},
	}, {
		sql: `
SELECT network_id, repository_id, incrementals
	FROM wiki_maintenance
 WHERE status IN ('completed', 'retry')
	 AND incrementals > 0
 ORDER BY incrementals DESC
 LIMIT ?
`,
		want: &QueryInfo{sqlparser.StmtSelect, []string{"wiki_maintenance"}},
	}, {
		sql: `
SELECT repo_name, incrementals
	FROM gist_maintenance
 WHERE status IN ('completed', 'retry')
	 AND incrementals > 0
 ORDER BY incrementals DESC
 LIMIT ?
`,
		want: &QueryInfo{sqlparser.StmtSelect, []string{"gist_maintenance"}},
	}, {
		sql: `
SELECT DISTINCT ri.*
	FROM repository_incrementals ri
-- The ones before the given merge
	JOIN repository_bases rb
		ON ri.network_id=rb.network_id AND ri.id<rb.incremental_id
-- But we want to leave out those which are not their groupwise max
LEFT JOIN repository_incrementals ri2
			 ON ri.network_id=ri2.network_id AND ri.repository_id=ri2.repository_id AND ri2.id>ri.id
 WHERE rb.id = ? AND ri2.id IS NOT NULL
`,
		want: &QueryInfo{sqlparser.StmtSelect, []string{"repository_bases", "repository_incrementals"}},
	}, {
		sql: `
SELECT wi.*
	FROM wiki_incrementals wi
	JOIN wiki_bases wb ON wi.network_id=wb.network_id AND wi.repository_id=wb.repository_id
 WHERE wb.id = ? AND wi.id < wb.incremental_id
`,
		want: &QueryInfo{sqlparser.StmtSelect, []string{"wiki_bases", "wiki_incrementals"}},
	}, {
		sql: `
SELECT gi.*
	FROM gist_incrementals gi
	JOIN gist_bases gb ON gi.repo_name=gb.repo_name
 WHERE gb.id = ? AND gi.id < gb.incremental_id
`,
		want: &QueryInfo{sqlparser.StmtSelect, []string{"gist_bases", "gist_incrementals"}},
	}, {
		sql: "COMMIT", want: &QueryInfo{op: sqlparser.StmtCommit},
	},
	}

	for _, tt := range tests {
		got, err := ParseQuery(tt.sql)
		if err != nil {
			t.Errorf("ParseQuery() error = %v", err)
			return
		}
		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("ParseQuery() = %v, want %v", got, tt.want)
		}
	}
}
