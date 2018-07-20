import gql from 'graphql-tag'

export const ALL_INODES_QUERY = gql`
  query AllInodesQuery {
    Inode {
      name
    }
  }
`

export const ALL_SYSCALL_TABLES_QUERY = gql`
  query AllSyscallTablesQuery {
    SyscallTable {
      index
      name
    }
  }
`

export const ALL_SYSCALLS_FOR_TABLE = gql`
  query AllSyscallForTable($table_name: String!) {
    Syscall {
      index
      name
      address
      hasSyscall(name: $table_name) {
        name
      }
    }
  }
`
