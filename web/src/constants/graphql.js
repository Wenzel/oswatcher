import gql from 'graphql-tag'

export const ALL_INODES_QUERY = gql`
  query AllInodesQuery {
    Inode {
      name
    }
  }
`

export const ALL_SYSCALLS_QUERY = gql`
  query AllSyscallQuery {
    Syscall {
      table
      index
      name
      address
    }
  }
`
