import mongoose, { Types } from 'mongoose';
import { env } from 'process';

if (env.NODE_ENV && env.NODE_ENV === 'production') {
    mongoose.connect(`mongodb://${env.MDB_USR}:${env.MDB_PSW}@${env.MDB_IP}:27017/passless`, {
        authSource: 'admin',
        autoCreate: true,
        autoIndex: true,
    });
} else {
    mongoose.connect('mongodb://localhost:27017/admin', {
        autoCreate: true,
        autoIndex: true,
    });
}

export interface IWebAuthenticator {}
export interface IDevice {
    wrappedVaultKey: String;
    _id: Types.ObjectId;
}
export interface ISession {
    sid: String;
    user: Types.ObjectId;
    _id: Types.ObjectId;
}
export interface IFile {
    _id: Types.ObjectId;
    data: String;
    iv: String;
}
export interface IUser {
    _id: Types.ObjectId;
    username: String;
    authenticators: Array<IWebAuthenticator>;
    devices: Array<IDevice>;
    sessionIds: Array<String>;
    file: IFile;
    passphraseResetAllowed: Boolean;
    // TODO: could be better to use the PHC string format
    // https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md
    passphraseHash: Buffer;
    passphraseHashSalt: Buffer;
    passphraseKeySalt: String;
    passphraseWrappedVaultKey: String;
}

const webAuthenticatorSchema = new mongoose.Schema({
    pubKey: String,
});

const deviceSchema = new mongoose.Schema({
    wrappedVaultKey: String,
});

const sessionSchema = new mongoose.Schema({
    sid: {
        type: String,
        unique: true,
        index: true,
        required: true,
    },
    user: {
        type: Types.ObjectId,
        ref: 'User',
        required: true,
    },
});

const fileSchema = new mongoose.Schema({
    data: String,
    iv: String,
});

const userSchema = new mongoose.Schema({
    username: {
        type: String,
        unique: true,
        index: true,
        required: true,
    },
    authenticators: [webAuthenticatorSchema],
    devices: [deviceSchema],
    file: fileSchema,
    sessionIds: [String],
    passphraseResetAllowed: Boolean,
    passphraseHash: Buffer,
    passphraseHashSalt: Buffer,
    passphraseKeySalt: String,
    passphraseWrappedVaultKey: String,
});

export const WebAuthenticator =
    mongoose.models.WebAuthenticator || mongoose.model('WebAuthenticator', webAuthenticatorSchema);
export const Session = mongoose.models.Session || mongoose.model('Session', sessionSchema);
export const Device = mongoose.models.Device || mongoose.model('Device', deviceSchema);
export const File = mongoose.models.File || mongoose.model('File', fileSchema);
export const User = mongoose.models.User || mongoose.model('User', userSchema);
