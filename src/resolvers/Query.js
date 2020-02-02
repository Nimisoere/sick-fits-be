const {forwardTo} = require('prisma-binding');
const {hasPermission} = require('../utils');

const Query = {
    items: forwardTo('db'),
    item: forwardTo('db'),
    itemsConnection: forwardTo('db'),
    async me(parent, args, ctx, info){
        if(!ctx.request.userId) return null;
        const user = await ctx.db.query.user({
            where: {id: ctx.request.userId}
        }, info)
        return user;
    },
    async users(parent, args, ctx, info) {
        if(!ctx.request.userId) {
            throw new Error('You must be logged in!');
        }
        hasPermission(ctx.request.user, ['ADMIN', 'PERMISSIONUPDATE']);
        return ctx.db.query.users({}, info);
    },
    async order(parent, args, ctx, info){
        if(!ctx.request.userId) {
            throw new Error('You must be logged in!');
        }
        const order = await ctx.db.query.order({
            where: {id: args.id}
        }, info);
        const ownsOrder = order.user.id === ctx.request.userId;
        const hasPermissionToSeeOrder = ctx.request.user.permissions.includes('ADMIN');
        if(!ownsOrder || !hasPermissionToSeeOrder){
            throw new Error('Access Denied: You can\'t see this order')
        }
        return order;
    },
    async orders(parent, args, ctx, info){
        if(!ctx.request.userId) {
            throw new Error('You must be logged in!');
        }
        const hasPermission = ctx.request.user.permissions.includes('ADMIN');
        if(!hasPermission){
            throw new Error('Access Denied: You can\'t see orders');
        }
        const orders = await ctx.db.query.orders({
            where:{
                user: {id: ctx.request.userId}
            }
        }, info);
        return orders;
    }
}

module.exports = Query;
