<?php

namespace Dcblogdev\MsGraph\Resources\Emails;

use Dcblogdev\MsGraph\Facades\MsGraph;
use Dcblogdev\MsGraph\Validators\GraphQueryValidator;
use Exception;

class Emails extends MsGraph
{
    public function folders(): Folders
    {
        return new Folders;
    }

    private string $top = '';

    private string $skip = '';

    private string $subject = '';

    private string $body = '';

    private string $comment = '';

    private string $id = '';

    private array $to = [];

    private array $cc = [];

    private array $bcc = [];

    private array $attachments = [];

    private array $singleValueExtendedProperties = [];

    public function id(string $id): static
    {
        $this->id = $id;

        return $this;
    }

    public function to(array $to): static
    {
        $this->to = $to;

        return $this;
    }

    public function cc(array $cc): static
    {
        $this->cc = $cc;

        return $this;
    }

    public function bcc(array $bcc): static
    {
        $this->bcc = $bcc;

        return $this;
    }

    public function subject(string $subject): static
    {
        $this->subject = $subject;

        return $this;
    }

    public function body(string $body): static
    {
        $this->body = $body;

        return $this;
    }

    public function comment(string $comment): static
    {
        $this->comment = $comment;

        return $this;
    }

    public function attachments(array $attachments): static
    {
        $this->attachments = $attachments;

        return $this;
    }

    public function singleValueExtendedProperties(array $singleValueExtendedProperties): static
    {
        $this->singleValueExtendedProperties = $singleValueExtendedProperties;

        return $this;
    }

    public function top(string $top): static
    {
        $this->top = $top;

        return $this;
    }

    public function skip(string $skip): static
    {
        $this->skip = $skip;

        return $this;
    }

    /**
     * @throws Exception
     */
    public function get(string $folderIdOrName = 'Inbox', array $params = []): array
    {
        GraphQueryValidator::validate($params);

        $top = request('top', $this->top);
        $skip = request('skip', $this->skip);

        if ($top === '') {
            $top = 25;
        }

        if ($skip === '') {
            $skip = 0;
        }

        if ($params === []) {
            $params = [
                '$top' => $top,
                '$skip' => $skip,
                '$count' => 'true',
            ];
        }

        if ($this->isId($folderIdOrName)) {
            $folder = MsGraph::emails()->folders()->find($folderIdOrName);
        } else {
            $folder = MsGraph::emails()->folders()->findByName($folderIdOrName);
        }

        if ($folder !== []) {
            return MsGraph::get("me/mailFolders/".$folder['id']."/messages?".http_build_query($params));
        } else {
            throw new Exception('Email folder not found');
        }
    }

    public function find(string $id): array
    {
        return MsGraph::get('me/messages/'.$id);
    }

    public function findAttachments(string $id): array
    {
        return MsGraph::get('me/messages/'.$id.'/attachments');
    }

    public function findInlineAttachments(array $email): array
    {
        $attachments = self::findAttachments($email['id']);

        // replace every case of <img='cid:' with the base64 image
        $email['body']['content'] = preg_replace_callback(
            '~cid.*?"~',
            function (array $m) use ($attachments) {
                // remove the last quote
                $parts = explode('"', $m[0]);

                // remove cid:
                $contentId = str_replace('cid:', '', $parts[0]);

                // loop over the attachments
                foreach ($attachments['value'] as $file) {
                    // if there is a match
                    if ($file['contentId'] == $contentId) {
                        // return a base64 image with a quote
                        return 'data:'.$file['contentType'].';base64,'.$file['contentBytes'].'"';
                    }
                }

                return true;
            },
            $email['body']['content']
        );

        return $email;
    }

    /**
     * @throws Exception
     */
    public function send(): void
    {
        if (count($this->to) === 0) {
            throw new Exception('To is required.');
        }

        if ($this->subject === '') {
            throw new Exception('Subject is required.');
        }

        if (strlen($this->comment) > 0) {
            throw new Exception('Comment is only used for replies and forwarding, please use body instead.');
        }

        MsGraph::post('me/sendMail', self::prepareEmail());
    }

    /**
     * @throws Exception
     */
    public function reply(): void
    {
        if (strlen($this->id) === 0) {
            throw new Exception('email id is required.');
        }

        if (strlen($this->body) > 0) {
            throw new Exception('Body is only used for sending new emails, please use comment instead.');
        }

        MsGraph::post('me/messages/'.$this->id.'/replyAll', self::prepareEmail());
    }

    /**
     * @throws Exception
     */
    public function forward(): void
    {
        if (strlen($this->id) === 0) {
            throw new Exception('email id is required.');
        }

        if (strlen($this->body) > 0) {
            throw new Exception('Body is only used for sending new emails, please use comment instead.');
        }

        MsGraph::post('me/messages/'.$this->id.'/forward', self::prepareEmail());
    }

    public function delete(string $id): void
    {
        MsGraph::delete('me/messages/'.$id);
    }

    protected function prepareEmail(): array
    {
        $subject = $this->subject;
        $body = $this->body;
        $comment = $this->comment;
        $to = $this->to;
        $cc = $this->cc;
        $bcc = $this->bcc;
        $attachments = $this->attachments;
        $singleValueExtendedProperties = $this->singleValueExtendedProperties;

        $toArray = [];
        foreach ($to as $email) {
            $toArray[]['emailAddress'] = ['address' => $email];
        }

        $ccArray = [];
        foreach ($cc as $email) {
            $ccArray[]['emailAddress'] = ['address' => $email];
        }

        $bccArray = [];
        foreach ($bcc as $email) {
            $bccArray[]['emailAddress'] = ['address' => $email];
        }

        $attachmentArray = [];
        foreach ($attachments as $file) {
            if (array_key_exists('name', $file) && array_key_exists('contentBytes', $file)) {
                $attachmentArray[] = [
                    '@odata.type' => '#microsoft.graph.fileAttachment',
                    'name' => $file['name'],
                    'contentBytes' => $file['contentBytes'],
                ];
            } else {
                $path = pathinfo($file);

                $attachmentArray[] = [
                    '@odata.type' => '#microsoft.graph.fileAttachment',
                    'name' => $path['basename'],
                    'contentType' => mime_content_type($file),
                    'contentBytes' => base64_encode(file_get_contents($file)),
                ];
            }
        }

        $singleValueExtendedPropertiesarray = [];
        foreach ($singleValueExtendedProperties as $value) {
            $singleValueExtendedPropertiesarray[] = [
                'id' => $value['id'],
                'value' => $value['value'],
            ];
        }

        $envelope = [];
        if ($subject !== '') {
            $envelope['message']['subject'] = $subject;
        }

        if ($body !== '') {
            $envelope['message']['body'] = [
                'contentType' => 'html',
                'content' => $body,
            ];
        }

        if (count($toArray) > 0) {
            $envelope['message']['toRecipients'] = $toArray;
        }

        if (count($ccArray) > 0) {
            $envelope['message']['ccRecipients'] = $ccArray;
        }

        if (count($bccArray) > 0) {
            $envelope['message']['bccRecipients'] = $bccArray;
        }

        if (count($attachmentArray) > 0) {
            $envelope['message']['attachments'] = $attachmentArray;
        }

        if ($comment !== '') {
            $envelope['comment'] = $comment;
        }

        return $envelope;
    }

    private function isId(string $value): bool
    {
        // IDs are long, contain uppercase/lowercase letters, numbers, hyphens, dots, underscores, and end with '='
        return preg_match('/^[A-Za-z0-9\-_]+={0,2}$/', $value) && strlen($value) > 50;
    }
}
