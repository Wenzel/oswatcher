import gql from 'graphql-tag'

export const ALL_INODES_QUERY = gql`
  query AllInodesQuery {
    Inode {
      name
    }
  }
`
