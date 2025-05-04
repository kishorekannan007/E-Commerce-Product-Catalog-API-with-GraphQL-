require("dotenv").config();

const express = require("express");
const { graphqlHTTP } = require("express-graphql");
const {
  GraphQLSchema,
  GraphQLObjectType,
  GraphQLString,
  GraphQLFloat,
  GraphQLID,
  GraphQLList,
  GraphQLNonNull,
  GraphQLInt,
  GraphQLBoolean,
} = require("graphql");

const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB connected successfully!"))
  .catch(err => console.error(" MongoDB connection error:", err));

// Define Mongoose models
const Product = mongoose.model("Product", new mongoose.Schema({
  name: String,
  description: String,
  price: Number,
  category: String,
  brand: String,
  rating: Number
}));

const User = mongoose.model("User", new mongoose.Schema({
  username: { type: String, unique: true },
  password: String,
  isAdmin: Boolean
}));

// Define GraphQL types
const ProductType = new GraphQLObjectType({
  name: "Product",
  fields: () => ({
    id: { type: GraphQLID },
    name: { type: GraphQLString },
    description: { type: GraphQLString },
    price: { type: GraphQLFloat },
    category: { type: GraphQLString },
    brand: { type: GraphQLString },
    rating: { type: GraphQLFloat }
  })
});

const UserType = new GraphQLObjectType({
  name: "User",
  fields: () => ({
    id: { type: GraphQLID },
    username: { type: GraphQLString },
    isAdmin: { type: GraphQLBoolean }
  })
});

// Define Root Query
const RootQuery = new GraphQLObjectType({
  name: "Query",
  fields: {
    me: {
      type: UserType,
      resolve: (_, __, { user }) => {
        if (!user) throw new Error("Unauthorized");
        return User.findById(user.id);
      }
    },
    products: {
      type: new GraphQLList(ProductType),
      args: {
        category: { type: GraphQLString },
        brand: { type: GraphQLString },
        minPrice: { type: GraphQLFloat },
        maxPrice: { type: GraphQLFloat },
        sortBy: { type: GraphQLString },
        limit: { type: GraphQLInt },
        skip: { type: GraphQLInt }
      },
      resolve: async (_, args) => {
        let filter = {};
        if (args.category) filter.category = args.category;
        if (args.brand) filter.brand = args.brand;
        if (args.minPrice || args.maxPrice)
          filter.price = {
            ...(args.minPrice ? { $gte: args.minPrice } : {}),
            ...(args.maxPrice ? { $lte: args.maxPrice } : {})
          };

        let query = Product.find(filter);
        if (args.sortBy) query = query.sort(args.sortBy);
        if (args.skip) query = query.skip(args.skip);
        if (args.limit) query = query.limit(args.limit);

        return await query.exec();
      }
    }
  }
});

// Define Mutations
const Mutation = new GraphQLObjectType({
  name: "Mutation",
  fields: {
    register: {
      type: GraphQLString,
      args: {
        username: { type: new GraphQLNonNull(GraphQLString) },
        password: { type: new GraphQLNonNull(GraphQLString) },
        isAdmin: { type: GraphQLBoolean }
      },
      resolve: async (_, { username, password, isAdmin }) => {
        const existing = await User.findOne({ username });
        if (existing) throw new Error("Username already exists");
        const hashed = await bcrypt.hash(password, 10);
        await new User({ username, password: hashed, isAdmin: isAdmin || false }).save();
        return "User registered";
      }
    },
    login: {
      type: GraphQLString,
      args: {
        username: { type: new GraphQLNonNull(GraphQLString) },
        password: { type: new GraphQLNonNull(GraphQLString) }
      },
      resolve: async (_, { username, password }) => {
        const user = await User.findOne({ username });
        if (!user) throw new Error("User not found");
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) throw new Error("Invalid credentials");

        const token = jwt.sign(
          { id: user._id, isAdmin: user.isAdmin },
          process.env.JWT_SECRET,
          { expiresIn: "1d" }
        );
        return token;
      }
    },
    addProduct: {
      type: ProductType,
      args: {
        name: { type: new GraphQLNonNull(GraphQLString) },
        description: { type: GraphQLString },
        price: { type: new GraphQLNonNull(GraphQLFloat) },
        category: { type: GraphQLString },
        brand: { type: GraphQLString },
        rating: { type: GraphQLFloat }
      },
      resolve: async (_, args, { user }) => {
        if (!user?.isAdmin) throw new Error("Unauthorized");
        return new Product(args).save();
      }
    },
    updateProduct: {
      type: ProductType,
      args: {
        id: { type: new GraphQLNonNull(GraphQLID) },
        name: { type: GraphQLString },
        description: { type: GraphQLString },
        price: { type: GraphQLFloat },
        category: { type: GraphQLString },
        brand: { type: GraphQLString },
        rating: { type: GraphQLFloat }
      },
      resolve: async (_, args, { user }) => {
        if (!user?.isAdmin) throw new Error("Unauthorized");
        const updated = await Product.findByIdAndUpdate(args.id, args, { new: true });
        if (!updated) throw new Error("Product not found");
        return updated;
      }
    },
    deleteProduct: {
      type: GraphQLString,
      args: { id: { type: new GraphQLNonNull(GraphQLID) } },
      resolve: async (_, { id }, { user }) => {
        if (!user?.isAdmin) throw new Error("Unauthorized");
        const result = await Product.findByIdAndDelete(id);
        if (!result) throw new Error("Product not found");
        return "Product deleted successfully";
      }
    }
  }
});

// Create schema
const schema = new GraphQLSchema({ query: RootQuery, mutation: Mutation });

// Create Express app
const app = express();

// GraphQL endpoint with header editor enabled
app.use("/graphql", (req, res) => {
  graphqlHTTP({
    schema,
    graphiql: {
      headerEditorEnabled: true
    },
    context: (() => {
      const authHeader = req.headers.authorization || '';
      const token = authHeader.split(" ")[1];
      let user = null;
      if (token) {
        try {
          user = jwt.verify(token, process.env.JWT_SECRET);
        } catch (err) {
          console.error(" Invalid token");
        }
      }
      return { user };
    })()
  })(req, res);
});

// Start server
const PORT = process.env.PORT || 4000;
app.listen(PORT, () =>
  console.log(` Server ready at http://localhost:${PORT}/graphql`)
);
