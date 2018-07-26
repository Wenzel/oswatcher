import gql from 'graphql-tag'

export const ALL_OS_QUERY = gql`
  query AllInodesQuery {
    OS {
      _id
      name
    }
  }
`

export const OS_FOR_ID_QUERY = gql`
  query OSForId($id: Long!) {
    OS(_id: $id) {
      name
    }
  }
`

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

export const ALL_PROCESSES_QUERY = gql`
  query AllProcessesQuery($os_name: String!) {
    Process(orderBy: pid_asc) {
      process_addr
      name
      pid
      ppid
      thread_count
      handle_count
      wow64
      ownedBy(name: $os_name) {
        name
      }
    }
  }
`
