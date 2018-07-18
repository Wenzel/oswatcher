import gql from 'graphql-tag'

export const ALL_INODES_QUERY = gql`
  query AllInodesQuery {
    Inode(first: 1000) {
      _id
      name
    }
  }
`
